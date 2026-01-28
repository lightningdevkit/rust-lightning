//! Functional tests testing channel feerate handling.

use crate::events::{ClosureReason, Event};
use crate::ln::chan_utils::{
	self, commitment_tx_base_weight, CommitmentTransaction, HTLCOutputInCommitment,
	COMMITMENT_TX_WEIGHT_PER_HTLC,
};
use crate::ln::channel::{
	get_holder_selected_channel_reserve_satoshis, ANCHOR_OUTPUT_VALUE_SATOSHI,
	CONCURRENT_INBOUND_HTLC_FEE_BUFFER, MIN_AFFORDABLE_HTLC_COUNT,
};
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{
	self, BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent,
};
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::types::features::ChannelTypeFeatures;
use crate::util::config::UserConfig;
use crate::util::errors::APIError;

use lightning_macros::xtest;

use bitcoin::secp256k1::Secp256k1;

#[xtest(feature = "_externalize_tests")]
pub fn test_async_inbound_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &[&nodes[1]], 8000000);

	// A                                        B
	// update_fee                            ->
	// send (1) commitment_signed            -.
	//                                       <- update_add_htlc/commitment_signed
	// send (2) RAA (awaiting remote revoke) -.
	// (1) commitment_signed is delivered    ->
	//                                       .- send (3) RAA (awaiting remote revoke)
	// (2) RAA is delivered                  ->
	//                                       .- send (4) commitment_signed
	//                                       <- (3) RAA is delivered
	// send (5) commitment_signed            -.
	//                                       <- (4) commitment_signed is delivered
	// send (6) RAA                          -.
	// (5) commitment_signed is delivered    ->
	//                                       <- RAA
	// (6) RAA is delivered                  ->

	// First nodes[0] generates an update_fee
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
		// (1)
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 40000);
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[1].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, node_a_id);
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &payment_event.commitment_msg); // (2)
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	// deliver(1), generate (3):
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// nodes[1] is awaiting nodes[0] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack); // deliver (2)
	let bs_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(bs_update.update_add_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fulfill_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_malformed_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fee.is_none()); // (4)
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack); // deliver (3)
	let as_update = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert!(as_update.update_add_htlcs.is_empty()); // (5)
	assert!(as_update.update_fulfill_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_malformed_htlcs.is_empty()); // (5)
	assert!(as_update.update_fee.is_none()); // (5)
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_update.commitment_signed); // deliver (4)
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// only (6) so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_update.commitment_signed); // deliver (5)
	let bs_second_revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_revoke);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_revoke); // deliver (6)
	check_added_monitors(&nodes[1], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee_unordered_raa() {
	// Just the intro to the previous test followed by an out-of-order RAA (which caused a
	// crash in an earlier version of the update_fee patch)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &[&nodes[1]], 8000000);

	// First nodes[0] generates an update_fee
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let update_msg = match events_0[0] {
		// (1)
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, .. },
			..
		} => update_fee.as_ref(),
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 40000);
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[1].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, node_a_id);
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &payment_event.commitment_msg); // (2)
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_msg); // deliver (2)
	check_added_monitors(&nodes[1], 1);

	// We can't continue, sadly, because our (1) now has a bogus signature
}

#[xtest(feature = "_externalize_tests")]
pub fn test_multi_flight_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	// A                                        B
	// update_fee/commitment_signed          ->
	//                                       .- send (1) RAA and (2) commitment_signed
	// update_fee (never committed)          ->
	// (3) update_fee                        ->
	// We have to manually generate the above update_fee, it is allowed by the protocol but we
	// don't track which updates correspond to which revoke_and_ack responses so we're in
	// AwaitingRAA mode and will not generate the update_fee yet.
	//                                       <- (1) RAA delivered
	// (3) is generated and send (4) CS      -.
	// Note that A cannot generate (4) prior to (1) being delivered as it otherwise doesn't
	// know the per_commitment_point to use for it.
	//                                       <- (2) commitment_signed delivered
	// revoke_and_ack                        ->
	//                                          B should send no response here
	// (4) commitment_signed delivered       ->
	//                                       <- RAA/commitment_signed delivered
	// revoke_and_ack                        ->

	// First nodes[0] generates an update_fee
	let initial_feerate;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		initial_feerate = *feerate_lock;
		*feerate_lock = initial_feerate + 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg_1, commitment_signed_1) = match events_0[0] {
		// (1)
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref().unwrap(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	// Deliver first update_fee/commitment_signed pair, generating (1) and (2):
	nodes[1].node.handle_update_fee(node_a_id, update_msg_1);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed_1);
	let (bs_revoke_msg, bs_commitment_signed) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	// nodes[0] is awaiting a revoke from nodes[1] before it will create a new commitment
	// transaction:
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = initial_feerate + 40;
	}
	nodes[0].node.timer_tick_occurred();
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Create the (3) update_fee message that nodes[0] will generate before it does...
	let mut update_msg_2 = msgs::UpdateFee {
		channel_id: update_msg_1.channel_id.clone(),
		feerate_per_kw: (initial_feerate + 30) as u32,
	};

	nodes[1].node.handle_update_fee(node_a_id, &update_msg_2);

	update_msg_2.feerate_per_kw = (initial_feerate + 40) as u32;
	// Deliver (3)
	nodes[1].node.handle_update_fee(node_a_id, &update_msg_2);

	// Deliver (1), generating (3) and (4)
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_msg);
	let as_second_update = get_htlc_update_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 1);
	assert!(as_second_update.update_add_htlcs.is_empty());
	assert!(as_second_update.update_fulfill_htlcs.is_empty());
	assert!(as_second_update.update_fail_htlcs.is_empty());
	assert!(as_second_update.update_fail_malformed_htlcs.is_empty());
	// Check that the update_fee newly generated matches what we delivered:
	assert_eq!(as_second_update.update_fee.as_ref().unwrap().channel_id, update_msg_2.channel_id);
	assert_eq!(
		as_second_update.update_fee.as_ref().unwrap().feerate_per_kw,
		update_msg_2.feerate_per_kw
	);

	// Deliver (2) commitment_signed
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_commitment_signed);
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	check_added_monitors(&nodes[0], 1);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	// Delever (4)
	nodes[1]
		.node
		.handle_commitment_signed_batch_test(node_a_id, &as_second_update.commitment_signed);
	let (bs_second_revoke, bs_second_commitment) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_revoke);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_second_commitment);
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_revoke);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee_vanilla() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 25;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);
}

pub fn do_test_update_fee_that_funder_cannot_afford(channel_type_features: ChannelTypeFeatures) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let mut default_config = test_default_channel_config();
	if channel_type_features == ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies() {
		default_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	}

	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(default_config.clone()), Some(default_config.clone())],
	);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_value = 5000;
	let push_sats = 700;
	let chan = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		channel_value,
		push_sats * 1000,
	);
	let channel_id = chan.2;
	let secp_ctx = Secp256k1::new();
	let bs_channel_reserve_sats =
		get_holder_selected_channel_reserve_satoshis(channel_value, &default_config);
	let (anchor_outputs_value_sats, outputs_num_no_htlcs) =
		if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
			(ANCHOR_OUTPUT_VALUE_SATOSHI * 2, 4)
		} else {
			(0, 2)
		};

	// Calculate the maximum feerate that A can afford. Note that we don't send an update_fee
	// CONCURRENT_INBOUND_HTLC_FEE_BUFFER HTLCs before actually running out of local balance, so we
	// calculate two different feerates here - the expected local limit as well as the expected
	// remote limit.
	let feerate =
		((channel_value - bs_channel_reserve_sats - push_sats - anchor_outputs_value_sats) * 1000
			/ (commitment_tx_base_weight(&channel_type_features)
				+ CONCURRENT_INBOUND_HTLC_FEE_BUFFER as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC)) as u32;
	let non_buffer_feerate =
		((channel_value - bs_channel_reserve_sats - push_sats - anchor_outputs_value_sats) * 1000
			/ commitment_tx_base_weight(&channel_type_features)) as u32;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = feerate;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let update_msg = get_htlc_update_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_update_fee(node_a_id, &update_msg.update_fee.unwrap());

	do_commitment_signed_dance(&nodes[1], &nodes[0], &update_msg.commitment_signed, false, false);

	// Confirm that the new fee based on the last local commitment txn is what we expected based on the feerate set above.
	{
		let commitment_tx = get_local_commitment_txn!(nodes[1], channel_id)[0].clone();

		// We made sure neither party's funds are below the dust limit and there are no HTLCs here
		assert_eq!(commitment_tx.output.len(), outputs_num_no_htlcs);
		let total_fee: u64 = commit_tx_fee_msat(feerate, 0, &channel_type_features) / 1000;
		let mut actual_fee =
			commitment_tx.output.iter().fold(0, |acc, output| acc + output.value.to_sat());
		actual_fee = channel_value - actual_fee;
		assert_eq!(total_fee, actual_fee);
	}

	{
		// Increment the feerate by a small constant, accounting for rounding errors
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 4;
	}
	nodes[0].node.timer_tick_occurred();
	let err = format!("Cannot afford to send new feerate at {}", feerate + 4);
	nodes[0].logger.assert_log("lightning::ln::channel", err, 1);
	check_added_monitors(&nodes[0], 0);

	const INITIAL_COMMITMENT_NUMBER: u64 = 281474976710654;

	let remote_point = {
		let mut per_peer_lock;
		let mut peer_state_lock;

		let channel = get_channel_ref!(nodes[1], nodes[0], per_peer_lock, peer_state_lock, chan.2);
		let chan_signer = channel.as_funded().unwrap().get_signer();
		let point_number = INITIAL_COMMITMENT_NUMBER - 1;
		chan_signer.as_ref().get_per_commitment_point(point_number, &secp_ctx).unwrap()
	};

	let res = {
		let mut per_peer_lock;
		let mut peer_state_lock;

		let local_chan =
			get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan.2);
		let local_chan_signer = local_chan.as_funded().unwrap().get_signer();

		let nondust_htlcs: Vec<HTLCOutputInCommitment> = vec![];
		let commitment_tx = CommitmentTransaction::new(
			INITIAL_COMMITMENT_NUMBER - 1,
			&remote_point,
			push_sats,
			channel_value
				- push_sats - anchor_outputs_value_sats
				- commit_tx_fee_msat(non_buffer_feerate + 4, 0, &channel_type_features) / 1000,
			non_buffer_feerate + 4,
			nondust_htlcs,
			&local_chan.funding().channel_transaction_parameters.as_counterparty_broadcastable(),
			&secp_ctx,
		);
		let params = &local_chan.funding().channel_transaction_parameters;
		local_chan_signer
			.as_ecdsa()
			.unwrap()
			.sign_counterparty_commitment(params, &commitment_tx, Vec::new(), Vec::new(), &secp_ctx)
			.unwrap()
	};

	let commit_signed_msg = msgs::CommitmentSigned {
		channel_id: chan.2,
		signature: res.0,
		htlc_signatures: res.1,
		funding_txid: None,
		#[cfg(taproot)]
		partial_signature_with_nonce: None,
	};

	let update_fee = msgs::UpdateFee { channel_id: chan.2, feerate_per_kw: non_buffer_feerate + 4 };

	nodes[1].node.handle_update_fee(node_a_id, &update_fee);

	//While producing the commitment_signed response after handling a received update_fee request the
	//check to see if the funder, who sent the update_fee request, can afford the new fee (funder_balance >= fee+channel_reserve)
	//Should produce and error.
	nodes[1].node.handle_commitment_signed(node_a_id, &commit_signed_msg);
	let err = "Funding remote cannot afford proposed new fee";
	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", err, 3);
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	let reason = ClosureReason::ProcessingError { err: err.to_string() };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], channel_value);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee_that_funder_cannot_afford() {
	do_test_update_fee_that_funder_cannot_afford(ChannelTypeFeatures::only_static_remote_key());
	do_test_update_fee_that_funder_cannot_afford(
		ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee_that_saturates_subs() {
	// Check that when a remote party sends us an `update_fee` message that results in a total fee
	// on the commitment transaction that is greater than her balance, we saturate the subtractions,
	// and force close the channel.

	let mut default_config = test_default_channel_config();
	let secp_ctx = Secp256k1::new();

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(default_config.clone()), Some(default_config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let chan_id = create_chan_between_nodes_with_value(&nodes[0], &nodes[1], 10_000, 8_500_000).3;

	const FEERATE: u32 = 250 * 10; // 10sat/vb

	// Assert that the new feerate will completely exhaust the balance of node 0, and saturate the
	// subtraction of the total fee from node 0's balance.
	let total_fee_sat = chan_utils::commit_tx_fee_sat(FEERATE, 0, &ChannelTypeFeatures::empty());
	assert!(total_fee_sat > 1500);

	const INITIAL_COMMITMENT_NUMBER: u64 = 281474976710654;

	// We build a commitment transcation here only to pass node 1's check of node 0's signature
	// in `commitment_signed`.

	let remote_point = {
		let mut per_peer_lock;
		let mut peer_state_lock;

		let channel = get_channel_ref!(nodes[1], nodes[0], per_peer_lock, peer_state_lock, chan_id);
		let chan_signer = channel.as_funded().unwrap().get_signer();
		chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER, &secp_ctx).unwrap()
	};

	let res = {
		let mut per_peer_lock;
		let mut peer_state_lock;

		let local_chan =
			get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_id);
		let local_chan_signer = local_chan.as_funded().unwrap().get_signer();
		let nondust_htlcs: Vec<HTLCOutputInCommitment> = vec![];
		let commitment_tx = CommitmentTransaction::new(
			INITIAL_COMMITMENT_NUMBER,
			&remote_point,
			8500,
			// Set a zero balance here: this is the transaction that node 1 will expect a signature for, as
			// he will do a saturating subtraction of the total fees from node 0's balance.
			0,
			FEERATE,
			nondust_htlcs,
			&local_chan.funding().channel_transaction_parameters.as_counterparty_broadcastable(),
			&secp_ctx,
		);
		let params = &local_chan.funding().channel_transaction_parameters;
		local_chan_signer
			.as_ecdsa()
			.unwrap()
			.sign_counterparty_commitment(params, &commitment_tx, Vec::new(), Vec::new(), &secp_ctx)
			.unwrap()
	};

	let commit_signed_msg = msgs::CommitmentSigned {
		channel_id: chan_id,
		signature: res.0,
		htlc_signatures: res.1,
		funding_txid: None,
		#[cfg(taproot)]
		partial_signature_with_nonce: None,
	};

	let update_fee = msgs::UpdateFee { channel_id: chan_id, feerate_per_kw: FEERATE };

	nodes[1].node.handle_update_fee(node_a_id, &update_fee);

	nodes[1].node.handle_commitment_signed(node_a_id, &commit_signed_msg);
	let err = "Funding remote cannot afford proposed new fee";
	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", err, 3);
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	let reason = ClosureReason::ProcessingError { err: err.to_string() };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 10_000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee_with_fundee_update_add_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &[&nodes[1]], 8000000);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 800000);

	// nothing happens since node[1] is in AwaitingRemoteRevoke
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[1].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	// node[1] has nothing to do

	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_msg);
	check_added_monitors(&nodes[1], 1);
	// AwaitingRemoteRevoke ends here

	let commitment_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(commitment_update.update_add_htlcs.len(), 1);
	assert_eq!(commitment_update.update_fulfill_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_malformed_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fee.is_none(), true);

	nodes[0].node.handle_update_add_htlc(node_b_id, &commitment_update.update_add_htlcs[0]);
	nodes[0]
		.node
		.handle_commitment_signed_batch_test(node_b_id, &commitment_update.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let (revoke, commitment_signed) = get_revoke_commit_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke);
	check_added_monitors(&nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	expect_and_process_pending_htlcs(&nodes[0], false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { .. } => {},
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[1], &[&nodes[0]], our_payment_preimage);

	send_payment(&nodes[1], &[&nodes[0]], 800000);
	send_payment(&nodes[0], &[&nodes[1]], 800000);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	let node_a_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, node_a_reason, &[node_b_id], 100000);
	let node_b_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_a_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let channel_id = chan.2;

	// A                                        B
	// (1) update_fee/commitment_signed      ->
	//                                       <- (2) revoke_and_ack
	//                                       .- send (3) commitment_signed
	// (4) update_fee/commitment_signed      ->
	//                                       .- send (5) revoke_and_ack (no CS as we're awaiting a revoke)
	//                                       <- (3) commitment_signed delivered
	// send (6) revoke_and_ack               -.
	//                                       <- (5) deliver revoke_and_ack
	// (6) deliver revoke_and_ack            ->
	//                                       .- send (7) commitment_signed in response to (4)
	//                                       <- (7) deliver commitment_signed
	// revoke_and_ack                        ->

	// Create and deliver (1)...
	let feerate;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		feerate = *feerate_lock;
		*feerate_lock = feerate + 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	// Generate (2) and (3):
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let (revoke_msg, commitment_signed_0) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	// Deliver (2):
	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	// Create and deliver (4)...
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = feerate + 30;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	check_added_monitors(&nodes[1], 1);
	// ... creating (5)
	let revoke_msg = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Handle (3), creating (6):
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed_0);
	check_added_monitors(&nodes[0], 1);
	let revoke_msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Deliver (5):
	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	// Deliver (6), creating (7):
	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_msg_0);
	let commitment_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(commitment_update.update_add_htlcs.is_empty());
	assert!(commitment_update.update_fulfill_htlcs.is_empty());
	assert!(commitment_update.update_fail_htlcs.is_empty());
	assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
	assert!(commitment_update.update_fee.is_none());
	check_added_monitors(&nodes[1], 1);

	// Deliver (7)
	nodes[0]
		.node
		.handle_commitment_signed_batch_test(node_b_id, &commitment_update.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_msg);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(get_feerate!(nodes[0], nodes[1], channel_id), feerate + 30);
	assert_eq!(get_feerate!(nodes[1], nodes[0], channel_id), feerate + 30);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	let node_a_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, node_a_reason, &[node_b_id], 100000);
	let node_b_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_a_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_chan_init_feerate_unaffordability() {
	// Test that we will reject channel opens which do not leave enough to pay for any HTLCs due to
	// channel reserve and feerate requirements.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let default_config = UserConfig::default();
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	// Set the push_msat amount such that nodes[0] will not be able to afford to add even a single
	// HTLC.
	let mut push_amt = 100_000_000;
	push_amt -= commit_tx_fee_msat(
		feerate_per_kw,
		MIN_AFFORDABLE_HTLC_COUNT as u64,
		&channel_type_features,
	);
	assert_eq!(nodes[0].node.create_channel(node_b_id, 100_000, push_amt + 1, 42, None, None).unwrap_err(),
		APIError::APIMisuseError { err: "Funding amount (356) can't even pay fee for initial commitment transaction fee of 357.".to_string() });

	// During open, we don't have a "counterparty channel reserve" to check against, so that
	// requirement only comes into play on the open_channel handling side.
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;
	nodes[0].node.create_channel(node_b_id, 100_000, push_amt, 42, None, None).unwrap();
	let mut open_channel_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	open_channel_msg.push_msat += 1;
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, .. } => {
			assert!(nodes[1]
				.node
				.accept_inbound_channel(temporary_channel_id, counterparty_node_id, 42, None,)
				.is_err());
		},
		_ => panic!("Unexpected event"),
	}

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg }, ..
		} => {
			assert_eq!(msg.data, "Insufficient funding amount for initial reserve");
		},
		_ => panic!("Unexpected event"),
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn accept_busted_but_better_fee() {
	// If a peer sends us a fee update that is too low, but higher than our previous channel
	// feerate, we should accept it. In the future we may want to consider closing the channel
	// later, but for now we only accept the update.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	create_chan_between_nodes(&nodes[0], &nodes[1]);

	// Set nodes[1] to expect 5,000 sat/kW.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 5000;
	}

	// If nodes[0] increases their feerate, even if its not enough, nodes[1] should accept it.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 1000;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => {
			nodes[1].node.handle_update_fee(node_a_id, update_fee.as_ref().unwrap());
			do_commitment_signed_dance(&nodes[1], &nodes[0], &commitment_signed, false, false);
		},
		_ => panic!("Unexpected event"),
	};

	// If nodes[0] increases their feerate further, even if its not enough, nodes[1] should accept
	// it.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 2000;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => {
			nodes[1].node.handle_update_fee(node_a_id, update_fee.as_ref().unwrap());
			do_commitment_signed_dance(&nodes[1], &nodes[0], &commitment_signed, false, false);
		},
		_ => panic!("Unexpected event"),
	};

	// However, if nodes[0] decreases their feerate, nodes[1] should reject it and close the
	// channel.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 1000;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, .. },
			..
		} => {
			nodes[1].node.handle_update_fee(node_a_id, update_fee.as_ref().unwrap());
			let reason = ClosureReason::PeerFeerateTooLow {
				peer_feerate_sat_per_kw: 1000,
				required_feerate_sat_per_kw: 5000,
			};
			check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors(&nodes[1], 1);
		},
		_ => panic!("Unexpected event"),
	};
}

#[xtest(feature = "_externalize_tests")]
pub fn cannot_afford_on_holding_cell_release() {
	do_cannot_afford_on_holding_cell_release(ChannelTypeFeatures::only_static_remote_key(), true);
	do_cannot_afford_on_holding_cell_release(ChannelTypeFeatures::only_static_remote_key(), false);
	do_cannot_afford_on_holding_cell_release(
		ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
		true,
	);
	do_cannot_afford_on_holding_cell_release(
		ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
		false,
	);
}

pub fn do_cannot_afford_on_holding_cell_release(
	channel_type_features: ChannelTypeFeatures, can_afford: bool,
) {
	// Test that if we can't afford a feerate update when releasing an
	// update_fee from its holding cell, we do not generate any msg events
	let chanmon_cfgs = create_chanmon_cfgs(2);

	let mut default_config = test_default_channel_config();
	default_config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel =
		100;
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
		default_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	}

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(default_config.clone()), Some(default_config)]);

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let target_feerate = 1000;
	let expected_tx_fee_sat =
		chan_utils::commit_tx_fee_sat(target_feerate, 1, &channel_type_features);
	// This is the number of htlcs that `send_update_fee` will account for when checking whether
	// it can afford the new feerate upon releasing an update_fee from its holding cell,
	// ie the buffer + the inbound HTLC we will add while the update_fee is in the holding cell
	let buffer_htlcs = crate::ln::channel::CONCURRENT_INBOUND_HTLC_FEE_BUFFER as usize + 1;
	let buffer_tx_fee_sat =
		chan_utils::commit_tx_fee_sat(target_feerate, buffer_htlcs, &channel_type_features);
	let anchor_value_satoshis = if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
		2 * crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI
	} else {
		0
	};
	let channel_reserve_satoshis = 1000;

	let channel_value_sat = 100_000;
	let node_0_balance_sat = buffer_tx_fee_sat + anchor_value_satoshis + channel_reserve_satoshis
		- if can_afford { 0 } else { 1 };
	let node_1_balance_sat = channel_value_sat - node_0_balance_sat;

	let chan_id =
		create_chan_between_nodes_with_value(&nodes[0], &nodes[1], channel_value_sat, 0).3;

	// Set node 0's balance to the can/can't afford threshold
	send_payment(&nodes[0], &[&nodes[1]], node_1_balance_sat * 1000);

	{
		// Sanity check the reserve
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[1], nodes[0], per_peer_state_lock, peer_state_lock, chan_id);
		assert_eq!(
			chan.funding().holder_selected_channel_reserve_satoshis,
			channel_reserve_satoshis
		);
	}

	{
		// Bump the feerate
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = target_feerate;
	}

	// Put the update fee into the holding cell of node 0

	nodes[0].node.maybe_update_chan_fees();

	// While the update_fee is in the holding cell, add an inbound HTLC

	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 5000 * 1000);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[1].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.pop().unwrap())
	};
	assert_eq!(payment_event.node_id, node_a_id);
	assert_eq!(payment_event.msgs.len(), 1);

	nodes[0].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(node_b_id, &payment_event.commitment_msg[0]);
	check_added_monitors(&nodes[0], 1);

	let (revoke_ack, commitment_signed) = get_revoke_commit_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_ack);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_commitment_signed(node_a_id, &commitment_signed[0]);
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	if let MessageSendEvent::SendRevokeAndACK { node_id, msg } = events.pop().unwrap() {
		assert_eq!(node_id, node_a_id);
		nodes[0].node.handle_revoke_and_ack(node_b_id, &msg);
		check_added_monitors(&nodes[0], 1);
	} else {
		panic!();
	}

	// Release the update_fee from its holding cell
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	if can_afford {
		// We could afford the update_fee, sanity check everything
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates } =
			events.pop().unwrap()
		{
			assert_eq!(node_id, node_b_id);
			assert_eq!(channel_id, chan_id);
			assert_eq!(updates.commitment_signed.len(), 1);
			assert_eq!(updates.commitment_signed[0].htlc_signatures.len(), 1);
			assert_eq!(updates.update_add_htlcs.len(), 0);
			assert_eq!(updates.update_fulfill_htlcs.len(), 0);
			assert_eq!(updates.update_fail_htlcs.len(), 0);
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 0);
			let update_fee = updates.update_fee.unwrap();
			assert_eq!(update_fee.channel_id, chan_id);
			assert_eq!(update_fee.feerate_per_kw, target_feerate);

			nodes[1].node.handle_update_fee(node_a_id, &update_fee);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);

			// Confirm the feerate on node 0's commitment transaction
			{
				let commitment_tx = get_local_commitment_txn!(nodes[0], channel_id)[0].clone();

				let mut actual_fee =
					commitment_tx.output.iter().fold(0, |acc, output| acc + output.value.to_sat());
				actual_fee = channel_value_sat - actual_fee;
				assert_eq!(expected_tx_fee_sat, actual_fee);
			}

			// Confirm the feerate on node 1's commitment transaction
			{
				let commitment_tx = get_local_commitment_txn!(nodes[1], channel_id)[0].clone();

				let mut actual_fee =
					commitment_tx.output.iter().fold(0, |acc, output| acc + output.value.to_sat());
				actual_fee = channel_value_sat - actual_fee;
				assert_eq!(expected_tx_fee_sat, actual_fee);
			}
		} else {
			panic!();
		}
	} else {
		// We could not afford the update_fee, no events should be generated
		assert_eq!(events.len(), 0);
		let err = format!("Cannot afford to send new feerate at {}", target_feerate);
		nodes[0].logger.assert_log("lightning::ln::channel", err, 1);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn can_afford_given_trimmed_htlcs() {
	do_can_afford_given_trimmed_htlcs(core::cmp::Ordering::Equal);
	do_can_afford_given_trimmed_htlcs(core::cmp::Ordering::Greater);
	do_can_afford_given_trimmed_htlcs(core::cmp::Ordering::Less);
}

pub fn do_can_afford_given_trimmed_htlcs(inequality_regions: core::cmp::Ordering) {
	// Test that when we check whether we can afford a feerate update, we account for the
	// decrease in the weight of the commitment transaction due to newly trimmed HTLCs at the higher feerate.
	//
	// Place a non-dust HTLC on the transaction, increase the feerate such that the HTLC
	// gets trimmed, and finally check whether we were able to afford the new feerate.

	let channel_type = ChannelTypeFeatures::only_static_remote_key();
	let can_afford = match inequality_regions {
		core::cmp::Ordering::Less => false,
		core::cmp::Ordering::Equal => true,
		core::cmp::Ordering::Greater => true,
	};
	let inequality_boundary_offset = match inequality_regions {
		core::cmp::Ordering::Less => 0,
		core::cmp::Ordering::Equal => 1,
		core::cmp::Ordering::Greater => 2,
	};

	let chanmon_cfgs = create_chanmon_cfgs(2);

	let mut default_config = test_default_channel_config();
	default_config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel =
		100;

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(default_config.clone()), Some(default_config)]);

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// We will update the feerate from 253sat/kw to 1000sat/kw
	let target_feerate = 1000;
	// Set a HTLC amount that is non-dust at 253sat/kw and dust at 1000sat/kw
	let node_0_inbound_htlc_amount_sat = 750;

	// This is the number of HTLCs that `can_send_update_fee` will account for when checking
	// whether node 0 can afford the target feerate. We do not include the inbound HTLC we will send,
	// as that HTLC will be trimmed at the new feerate.
	let buffer_tx_fee_sat = chan_utils::commit_tx_fee_sat(
		target_feerate,
		crate::ln::channel::CONCURRENT_INBOUND_HTLC_FEE_BUFFER as usize,
		&channel_type,
	);
	let channel_reserve_satoshis = 1000;

	let channel_value_sat = 100_000;
	let node_0_balance_sat =
		(buffer_tx_fee_sat + channel_reserve_satoshis) - 1 + inequality_boundary_offset;
	let node_1_balance_sat = channel_value_sat - node_0_balance_sat;

	let chan_id =
		create_chan_between_nodes_with_value(&nodes[0], &nodes[1], channel_value_sat, 0).3;
	{
		// Double check the reserve here
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[1], nodes[0], per_peer_state_lock, peer_state_lock, chan_id);
		assert_eq!(
			chan.funding().holder_selected_channel_reserve_satoshis,
			channel_reserve_satoshis
		);
	}

	// Set node 0's balance at some offset from the inequality boundary
	send_payment(&nodes[0], &[&nodes[1]], node_1_balance_sat * 1000);

	// Route the HTLC from node 1 to node 0
	route_payment(&nodes[1], &[&nodes[0]], node_0_inbound_htlc_amount_sat * 1000);

	// Confirm the feerate on node 0's commitment transaction
	{
		let expected_tx_fee_sat = chan_utils::commit_tx_fee_sat(253, 1, &channel_type);
		let commitment_tx = get_local_commitment_txn!(nodes[0], chan_id)[0].clone();

		let mut actual_fee = commitment_tx
			.output
			.iter()
			.map(|output| output.value.to_sat())
			.reduce(|acc, value| acc + value)
			.unwrap();
		actual_fee = channel_value_sat - actual_fee;
		assert_eq!(expected_tx_fee_sat, actual_fee);

		// The HTLC is non-dust...
		assert_eq!(commitment_tx.output.len(), 3);
	}

	{
		// Bump the feerate
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = target_feerate;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], if can_afford { 1 } else { 0 });
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();

	if can_afford {
		// We could afford the target feerate, sanity check everything
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates } =
			events.pop().unwrap()
		{
			assert_eq!(node_id, node_b_id);
			assert_eq!(channel_id, chan_id);
			assert_eq!(updates.commitment_signed.len(), 1);
			// The HTLC is now trimmed!
			assert_eq!(updates.commitment_signed[0].htlc_signatures.len(), 0);
			assert_eq!(updates.update_add_htlcs.len(), 0);
			assert_eq!(updates.update_fulfill_htlcs.len(), 0);
			assert_eq!(updates.update_fail_htlcs.len(), 0);
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 0);
			let update_fee = updates.update_fee.unwrap();
			assert_eq!(update_fee.channel_id, chan_id);
			assert_eq!(update_fee.feerate_per_kw, target_feerate);

			nodes[1].node.handle_update_fee(node_a_id, &update_fee);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);

			// Confirm the feerate on node 0's commitment transaction
			{
				// Also add the trimmed HTLC to the fees
				let expected_tx_fee_sat =
					chan_utils::commit_tx_fee_sat(target_feerate, 0, &channel_type)
						+ node_0_inbound_htlc_amount_sat;
				let commitment_tx = get_local_commitment_txn!(nodes[0], channel_id)[0].clone();

				let mut actual_fee = commitment_tx
					.output
					.iter()
					.map(|output| output.value.to_sat())
					.reduce(|acc, value| acc + value)
					.unwrap();
				actual_fee = channel_value_sat - actual_fee;
				assert_eq!(expected_tx_fee_sat, actual_fee);

				// The HTLC is now trimmed!
				assert_eq!(commitment_tx.output.len(), 2);
			}

			// Confirm the feerate on node 1's commitment transaction
			{
				// Also add the trimmed HTLC to the fees
				let expected_tx_fee_sat =
					chan_utils::commit_tx_fee_sat(target_feerate, 0, &channel_type)
						+ node_0_inbound_htlc_amount_sat;
				let commitment_tx = get_local_commitment_txn!(nodes[1], channel_id)[0].clone();

				let mut actual_fee = commitment_tx
					.output
					.iter()
					.map(|output| output.value.to_sat())
					.reduce(|acc, value| acc + value)
					.unwrap();
				actual_fee = channel_value_sat - actual_fee;
				assert_eq!(expected_tx_fee_sat, actual_fee);

				// The HTLC is now trimmed!
				assert_eq!(commitment_tx.output.len(), 2);
			}
		} else {
			panic!();
		}
	} else {
		// We could not afford the target feerate, no events should be generated
		assert_eq!(events.len(), 0);
		let err = format!("Cannot afford to send new feerate at {}", target_feerate);
		nodes[0].logger.assert_log("lightning::ln::channel", err, 1);
	}
}

#[test]
pub fn test_zero_fee_commitments_no_update_fee() {
	// Tests that option_zero_fee_commitment channels do not sent update_fee messages, and that
	// they'll disconnect and warn if they receive them.
	let mut cfg = test_default_channel_config();
	cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg.clone()), Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_chan_between_nodes(&nodes[0], &nodes[1]);

	let assert_zero_fee = || {
		for node in nodes.iter() {
			let channels = node.node.list_channels();
			assert_eq!(channels.len(), 1);
			assert!(channels[0]
				.channel_type
				.as_ref()
				.unwrap()
				.supports_anchor_zero_fee_commitments());
			assert_eq!(channels[0].feerate_sat_per_1000_weight.unwrap(), 0);
		}
	};
	assert_zero_fee();

	// Sender should not queue an update_fee message.
	nodes[0].node.timer_tick_occurred();
	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 0);

	// Receiver should ignore and warn if sent update_fee.
	let channel_id = channel.3;
	let update_fee_msg = msgs::UpdateFee { channel_id, feerate_per_kw: 5000 };
	nodes[1].node.handle_update_fee(nodes[0].node.get_our_node_id(), &update_fee_msg);

	let events_1 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::HandleError { ref action, .. } => match action {
			ErrorAction::DisconnectPeerWithWarning { ref msg, .. } => {
				assert_eq!(msg.channel_id, channel_id);
				assert!(msg
					.data
					.contains("Update fee message received for zero fee commitment channel"));
			},
			_ => panic!("Expected DisconnectPeerWithWarning, got {:?}", action),
		},
		_ => panic!("Expected HandleError event, got {:?}", events_1[0]),
	}
	assert_zero_fee();
}
