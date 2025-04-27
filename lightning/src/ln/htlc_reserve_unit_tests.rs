//! Various unit tests covering HTLC handling as well as tests covering channel reserve tracking.

use crate::events::{Event, PaymentPurpose};
use crate::ln::functional_test_utils::*;
use crate::ln::chan_utils::{commitment_tx_base_weight, COMMITMENT_TX_WEIGHT_PER_HTLC};
use crate::ln::channel::{FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, Channel, get_holder_selected_channel_reserve_satoshis};
use crate::ln::channelmanager::PaymentId;
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::util::config::UserConfig;
use crate::util::errors::APIError;
use crate::types::features::ChannelTypeFeatures;
use crate::routing::router::PaymentParameters;

use lightning_macros::xtest;

fn do_test_counterparty_no_reserve(send_from_initiator: bool) {
	// A peer providing a channel_reserve_satoshis of 0 (or less than our dust limit) is insecure,
	// but only for them. Because some LSPs do it with some level of trust of the clients (for a
	// substantial UX improvement), we explicitly allow it. Because it's unlikely to happen often
	// in normal testing, we test it explicitly here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let default_config = UserConfig::default();

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let mut push_amt = 100_000_000;
	let feerate_per_kw = 253;
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	push_amt -= feerate_per_kw as u64 * (commitment_tx_base_weight(&channel_type_features) + 4 * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000 * 1000;
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;

	let temp_channel_id = nodes[0].node.create_channel(node_b_id, 100_000, if send_from_initiator { 0 } else { push_amt }, 42, None, None).unwrap();
	let mut open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	if !send_from_initiator {
		open_channel_message.channel_reserve_satoshis = 0;
		open_channel_message.common_fields.max_htlc_value_in_flight_msat = 100_000_000;
	}
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_message);

	// Extract the channel accept message from node1 to node0
	let mut accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	if send_from_initiator {
		accept_channel_message.channel_reserve_satoshis = 0;
		accept_channel_message.common_fields.max_htlc_value_in_flight_msat = 100_000_000;
	}
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel_message);
	{
		let sender_node = if send_from_initiator { &nodes[1] } else { &nodes[0] };
		let counterparty_node = if send_from_initiator { &nodes[0] } else { &nodes[1] };
		let mut sender_node_per_peer_lock;
		let mut sender_node_peer_state_lock;

		let channel = get_channel_ref!(sender_node, counterparty_node, sender_node_per_peer_lock, sender_node_peer_state_lock, temp_channel_id);
		assert!(channel.is_unfunded_v1());
		channel.funding_mut().holder_selected_channel_reserve_satoshis = 0;
		channel.context_mut().holder_max_htlc_value_in_flight_msat = 100_000_000;
	}

	let funding_tx = sign_funding_transaction(&nodes[0], &nodes[1], 100_000, temp_channel_id);
	let funding_msgs = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &funding_tx);
	create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_msgs.0);

	// nodes[0] should now be able to send the full balance to nodes[1], violating nodes[1]'s
	// security model if it ever tries to send funds back to nodes[0] (but that's not our problem).
	if send_from_initiator {
		send_payment(&nodes[0], &[&nodes[1]], 100_000_000
			// Note that for outbound channels we have to consider the commitment tx fee and the
			// "fee spike buffer", which is currently a multiple of the total commitment tx fee as
			// well as an additional HTLC.
			- FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE * commit_tx_fee_msat(feerate_per_kw, 2, &channel_type_features));
	} else {
		send_payment(&nodes[1], &[&nodes[0]], push_amt);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_counterparty_no_reserve() {
	do_test_counterparty_no_reserve(true);
	do_test_counterparty_no_reserve(false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_reserve_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 239;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config.clone()), Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 190000, 1001);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 190000, 1001);
	let chan_2_user_id = nodes[2].node.list_channels()[0].user_channel_id;

	let mut stat01 = get_channel_value_stat!(nodes[0], nodes[1], chan_1.2);
	let mut stat11 = get_channel_value_stat!(nodes[1], nodes[0], chan_1.2);

	let mut stat12 = get_channel_value_stat!(nodes[1], nodes[2], chan_2.2);
	let mut stat22 = get_channel_value_stat!(nodes[2], nodes[1], chan_2.2);

	macro_rules! expect_forward {
		($node: expr) => {{
			let mut events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			check_added_monitors!($node, 1);
			let payment_event = SendEvent::from_event(events.remove(0));
			payment_event
		}}
	}

	let feemsat = 239; // set above
	let total_fee_msat = (nodes.len() - 2) as u64 * feemsat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan_1.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_1.2);

	let recv_value_0 = stat01.counterparty_max_htlc_value_in_flight_msat - total_fee_msat;

	// attempt to send amt_msat > their_max_htlc_value_in_flight_msat
	{
		let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
			.with_bolt11_features(nodes[2].node.bolt11_invoice_features()).unwrap().with_max_channel_saturation_power_of_half(0);
		let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, recv_value_0);
		route.paths[0].hops.last_mut().unwrap().fee_msat += 1;
		assert!(route.paths[0].hops.iter().rev().skip(1).all(|h| h.fee_msat == feemsat));

		unwrap_send_err!(nodes[0], nodes[0].node.send_payment_with_route(route, our_payment_hash,
				RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
			), true, APIError::ChannelUnavailable { .. }, {});
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// channel reserve is bigger than their_max_htlc_value_in_flight_msat so loop to deplete
	// nodes[0]'s wealth
	loop {
		let amt_msat = recv_value_0 + total_fee_msat;
		// 3 for the 3 HTLCs that will be sent, 2* and +1 for the fee spike reserve.
		// Also, ensure that each payment has enough to be over the dust limit to
		// ensure it'll be included in each commit tx fee calculation.
		let commit_tx_fee_all_htlcs = 2*commit_tx_fee_msat(feerate, 3 + 1, &channel_type_features);
		let ensure_htlc_amounts_above_dust_buffer = 3 * (stat01.counterparty_dust_limit_msat + 1000);
		if stat01.value_to_self_msat < stat01.channel_reserve_msat + commit_tx_fee_all_htlcs + ensure_htlc_amounts_above_dust_buffer + amt_msat {
			break;
		}

		let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
			.with_bolt11_features(nodes[2].node.bolt11_invoice_features()).unwrap().with_max_channel_saturation_power_of_half(0);
		let route = get_route!(nodes[0], payment_params, recv_value_0).unwrap();
		let (payment_preimage, ..) = send_along_route(&nodes[0], route, &[&nodes[1], &nodes[2]], recv_value_0);
		claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

		let (stat01_, stat11_, stat12_, stat22_) = (
			get_channel_value_stat!(nodes[0], nodes[1], chan_1.2),
			get_channel_value_stat!(nodes[1], nodes[0], chan_1.2),
			get_channel_value_stat!(nodes[1], nodes[2], chan_2.2),
			get_channel_value_stat!(nodes[2], nodes[1], chan_2.2),
		);

		assert_eq!(stat01_.value_to_self_msat, stat01.value_to_self_msat - amt_msat);
		assert_eq!(stat11_.value_to_self_msat, stat11.value_to_self_msat + amt_msat);
		assert_eq!(stat12_.value_to_self_msat, stat12.value_to_self_msat - (amt_msat - feemsat));
		assert_eq!(stat22_.value_to_self_msat, stat22.value_to_self_msat + (amt_msat - feemsat));
		stat01 = stat01_; stat11 = stat11_; stat12 = stat12_; stat22 = stat22_;
	}

	// adding pending output.
	// 2* and +1 HTLCs on the commit tx fee for the fee spike reserve.
	// The reason we're dividing by two here is as follows: the dividend is the total outbound liquidity
	// after fees, the channel reserve, and the fee spike buffer are removed. We eventually want to
	// divide this quantity into 3 portions, that will each be sent in an HTLC. This allows us
	// to test channel channel reserve policy at the edges of what amount is sendable, i.e.
	// cases where 1 msat over X amount will cause a payment failure, but anything less than
	// that can be sent successfully. So, dividing by two is a somewhat arbitrary way of getting
	// the amount of the first of these aforementioned 3 payments. The reason we split into 3 payments
	// is to test the behavior of the holding cell with respect to channel reserve and commit tx fee
	// policy.
	let commit_tx_fee_2_htlcs = 2*commit_tx_fee_msat(feerate, 2 + 1, &channel_type_features);
	let recv_value_1 = (stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat - commit_tx_fee_2_htlcs)/2;
	let amt_msat_1 = recv_value_1 + total_fee_msat;

	let (route_1, our_payment_hash_1, our_payment_preimage_1, our_payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[2], recv_value_1);
	let payment_event_1 = {
		nodes[0].node.send_payment_with_route(route_1.clone(), our_payment_hash_1,
			RecipientOnionFields::secret_only(our_payment_secret_1), PaymentId(our_payment_hash_1.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event_1.msgs[0]);

	// channel reserve test with htlc pending output > 0
	let recv_value_2 = stat01.value_to_self_msat - amt_msat_1 - stat01.channel_reserve_msat - total_fee_msat - commit_tx_fee_2_htlcs;
	{
		let mut route = route_1.clone();
		route.paths[0].hops.last_mut().unwrap().fee_msat = recv_value_2 + 1;
		let (_, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(nodes[2]);
		unwrap_send_err!(nodes[0], nodes[0].node.send_payment_with_route(route, our_payment_hash,
				RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
			), true, APIError::ChannelUnavailable { .. }, {});
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// split the rest to test holding cell
	let commit_tx_fee_3_htlcs = 2*commit_tx_fee_msat(feerate, 3 + 1, &channel_type_features);
	let additional_htlc_cost_msat = commit_tx_fee_3_htlcs - commit_tx_fee_2_htlcs;
	let recv_value_21 = recv_value_2/2 - additional_htlc_cost_msat/2;
	let recv_value_22 = recv_value_2 - recv_value_21 - total_fee_msat - additional_htlc_cost_msat;
	{
		let stat = get_channel_value_stat!(nodes[0], nodes[1], chan_1.2);
		assert_eq!(stat.value_to_self_msat - (stat.pending_outbound_htlcs_amount_msat + recv_value_21 + recv_value_22 + total_fee_msat + total_fee_msat + commit_tx_fee_3_htlcs), stat.channel_reserve_msat);
	}

	// now see if they go through on both sides
	let (route_21, our_payment_hash_21, our_payment_preimage_21, our_payment_secret_21) = get_route_and_payment_hash!(nodes[0], nodes[2], recv_value_21);
	// but this will stuck in the holding cell
	nodes[0].node.send_payment_with_route(route_21, our_payment_hash_21,
		RecipientOnionFields::secret_only(our_payment_secret_21), PaymentId(our_payment_hash_21.0)).unwrap();
	check_added_monitors!(nodes[0], 0);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0);

	// test with outbound holding cell amount > 0
	{
		let (mut route, our_payment_hash, _, our_payment_secret) =
			get_route_and_payment_hash!(nodes[0], nodes[2], recv_value_22);
		route.paths[0].hops.last_mut().unwrap().fee_msat += 1;
		unwrap_send_err!(nodes[0], nodes[0].node.send_payment_with_route(route, our_payment_hash,
				RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
			), true, APIError::ChannelUnavailable { .. }, {});
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	let (route_22, our_payment_hash_22, our_payment_preimage_22, our_payment_secret_22) = get_route_and_payment_hash!(nodes[0], nodes[2], recv_value_22);
	// this will also stuck in the holding cell
	nodes[0].node.send_payment_with_route(route_22, our_payment_hash_22,
		RecipientOnionFields::secret_only(our_payment_secret_22), PaymentId(our_payment_hash_22.0)).unwrap();
	check_added_monitors!(nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// flush the pending htlc
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event_1.commitment_msg);
	let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[1], node_a_id);
	check_added_monitors!(nodes[1], 1);

	// the pending htlc should be promoted to committed
	nodes[0].node.handle_revoke_and_ack(node_b_id, &as_revoke_and_ack);
	check_added_monitors!(nodes[0], 1);
	let commitment_update_2 = get_htlc_update_msgs!(nodes[0], node_b_id);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &as_commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_11 = expect_forward!(nodes[1]);
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event_11.msgs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event_11.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[2]);
	expect_payment_claimable!(nodes[2], our_payment_hash_1, our_payment_secret_1, recv_value_1);

	// flush the htlcs in the holding cell
	assert_eq!(commitment_update_2.update_add_htlcs.len(), 2);
	nodes[1].node.handle_update_add_htlc(node_a_id, &commitment_update_2.update_add_htlcs[0]);
	nodes[1].node.handle_update_add_htlc(node_a_id, &commitment_update_2.update_add_htlcs[1]);
	commitment_signed_dance!(nodes[1], nodes[0], &commitment_update_2.commitment_signed, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_3 = expect_forward!(nodes[1]);
	assert_eq!(payment_event_3.msgs.len(), 2);
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event_3.msgs[0]);
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event_3.msgs[1]);

	commitment_signed_dance!(nodes[2], nodes[1], &payment_event_3.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, amount_msat, receiver_node_id, ref via_channel_ids, .. } => {
			assert_eq!(our_payment_hash_21, *payment_hash);
			assert_eq!(recv_value_21, amount_msat);
			assert_eq!(node_c_id, receiver_node_id.unwrap());
			assert_eq!(*via_channel_ids, vec![(chan_2.2, Some(chan_2_user_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(our_payment_secret_21, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, amount_msat, receiver_node_id, ref via_channel_ids, .. } => {
			assert_eq!(our_payment_hash_22, *payment_hash);
			assert_eq!(recv_value_22, amount_msat);
			assert_eq!(node_c_id, receiver_node_id.unwrap());
			assert_eq!(*via_channel_ids, vec![(chan_2.2, Some(chan_2_user_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(our_payment_secret_22, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_1);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_21);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_22);

	let commit_tx_fee_0_htlcs = 2*commit_tx_fee_msat(feerate, 1, &channel_type_features);
	let recv_value_3 = commit_tx_fee_2_htlcs - commit_tx_fee_0_htlcs - total_fee_msat;
	send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], recv_value_3);

	let commit_tx_fee_1_htlc = 2*commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);
	let expected_value_to_self = stat01.value_to_self_msat - (recv_value_1 + total_fee_msat) - (recv_value_21 + total_fee_msat) - (recv_value_22 + total_fee_msat) - (recv_value_3 + total_fee_msat);
	let stat0 = get_channel_value_stat!(nodes[0], nodes[1], chan_1.2);
	assert_eq!(stat0.value_to_self_msat, expected_value_to_self);
	assert_eq!(stat0.value_to_self_msat, stat0.channel_reserve_msat + commit_tx_fee_1_htlc);

	let stat2 = get_channel_value_stat!(nodes[2], nodes[1], chan_2.2);
	assert_eq!(stat2.value_to_self_msat, stat22.value_to_self_msat + recv_value_1 + recv_value_21 + recv_value_22 + recv_value_3);
}

#[xtest(feature = "_externalize_tests")]
pub fn channel_reserve_in_flight_removes() {
	// In cases where one side claims an HTLC, it thinks it has additional available funds that it
	// can send to its counterparty, but due to update ordering, the other side may not yet have
	// considered those HTLCs fully removed.
	// This tests that we don't count HTLCs which will not be included in the next remote
	// commitment transaction towards the reserve value (as it implies no commitment transaction
	// will be generated which violates the remote reserve value).
	// This was broken previously, and discovered by the chanmon_fail_consistency fuzz test.
	// To test this we:
	//  * route two HTLCs from A to B (note that, at a high level, this test is checking that, when
	//    you consider the values of both of these HTLCs, B may not send an HTLC back to A, but if
	//    you only consider the value of the first HTLC, it may not),
	//  * start routing a third HTLC from A to B,
	//  * claim the first two HTLCs (though B will generate an update_fulfill for one, and put
	//    the other claim in its holding cell, as it immediately goes into AwaitingRAA),
	//  * deliver the first fulfill from B
	//  * deliver the update_add and an RAA from A, resulting in B freeing the second holding cell
	//    claim,
	//  * deliver A's response CS and RAA.
	//    This results in A having the second HTLC in AwaitingRemovedRemoteRevoke, but B having
	//    removed it fully. B now has the push_msat plus the first two HTLCs in value.
	//  * Now B happily sends another HTLC, potentially violating its reserve value from A's point
	//    of view (if A counts the AwaitingRemovedRemoteRevoke HTLC).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let b_chan_values = get_channel_value_stat!(nodes[1], nodes[0], chan_1.2);
	// Route the first two HTLCs.
	let payment_value_1 = b_chan_values.channel_reserve_msat - b_chan_values.value_to_self_msat - 10000;
	let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], payment_value_1);
	let (payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[1]], 20_000);

	// Start routing the third HTLC (this is just used to get everyone in the right state).
	let (route, payment_hash_3, payment_preimage_3, payment_secret_3) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
	let send_1 = {
		nodes[0].node.send_payment_with_route(route, payment_hash_3,
			RecipientOnionFields::secret_only(payment_secret_3), PaymentId(payment_hash_3.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	// Now claim both of the first two HTLCs on B's end, putting B in AwaitingRAA and generating an
	// initial fulfill/CS.
	nodes[1].node.claim_funds(payment_preimage_1);
	expect_payment_claimed!(nodes[1], payment_hash_1, payment_value_1);
	check_added_monitors!(nodes[1], 1);
	let bs_removes = get_htlc_update_msgs!(nodes[1], node_a_id);

	// This claim goes in B's holding cell, allowing us to have a pending B->A RAA which does not
	// remove the second HTLC when we send the HTLC back from B to A.
	nodes[1].node.claim_funds(payment_preimage_2);
	expect_payment_claimed!(nodes[1], payment_hash_2, 20_000);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, &bs_removes.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_removes.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);

	nodes[1].node.handle_update_add_htlc(node_a_id, &send_1.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &send_1.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	// B is already AwaitingRAA, so cant generate a CS here
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], node_b_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	// The second HTLCis removed, but as A is in AwaitingRAA it can't generate a CS here, so the
	// RAA that B generated above doesn't fully resolve the second HTLC from A's point of view.
	// However, the RAA A generates here *does* fully resolve the HTLC from B's point of view (as A
	// can no longer broadcast a commitment transaction with it and B has the preimage so can go
	// on-chain as necessary).
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, &bs_cs.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	expect_payment_sent(&nodes[0], payment_preimage_2, None, false, false);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash_3, payment_secret_3, 100000);

	// Note that as this RAA was generated before the delivery of the update_fulfill it shouldn't
	// resolve the second HTLC from A's point of view.
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);
	let as_cs = get_htlc_update_msgs!(nodes[0], node_b_id);

	// Now that B doesn't have the second RAA anymore, but A still does, send a payment from B back
	// to A to ensure that A doesn't count the almost-removed HTLC in update_add processing.
	let (route, payment_hash_4, payment_preimage_4, payment_secret_4) = get_route_and_payment_hash!(nodes[1], nodes[0], 10000);
	let send_2 = {
		nodes[1].node.send_payment_with_route(route, payment_hash_4,
			RecipientOnionFields::secret_only(payment_secret_4), PaymentId(payment_hash_4.0)).unwrap();
		check_added_monitors!(nodes[1], 1);
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[0].node.handle_update_add_htlc(node_b_id, &send_2.msgs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &send_2.commitment_msg);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	// Now just resolve all the outstanding messages/HTLCs for completeness...

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);
	let as_cs = get_htlc_update_msgs!(nodes[0], node_b_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_claimable!(nodes[0], payment_hash_4, payment_secret_4, 10000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_4);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);
}
