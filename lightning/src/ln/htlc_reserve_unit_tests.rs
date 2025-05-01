//! Various unit tests covering HTLC handling as well as tests covering channel reserve tracking.

use crate::events::{ClosureReason, Event, HTLCHandlingFailureType, PaymentPurpose};
use crate::ln::functional_test_utils::*;
use crate::ln::chan_utils::{self, CommitmentTransaction, htlc_success_tx_weight, commitment_tx_base_weight, COMMITMENT_TX_WEIGHT_PER_HTLC};
use crate::ln::channel::{FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, Channel, MIN_AFFORDABLE_HTLC_COUNT, get_holder_selected_channel_reserve_satoshis};
use crate::ln::channelmanager::PaymentId;
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::ln::onion_utils;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::util::config::UserConfig;
use crate::util::errors::APIError;
use crate::types::features::ChannelTypeFeatures;
use crate::routing::router::PaymentParameters;

use lightning_macros::xtest;

use bitcoin::secp256k1::{Secp256k1, SecretKey};

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

#[xtest(feature = "_externalize_tests")]
pub fn holding_cell_htlc_counting() {
	// Tests that HTLCs in the holding cell count towards the pending HTLC limits on outbound HTLCs
	// to ensure we don't end up with HTLCs sitting around in our holding cell for several
	// commitment dance rounds.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Fetch a route in advance as we will be unable to once we're unable to send.
	let (route, payment_hash_1, _, payment_secret_1) = get_route_and_payment_hash!(nodes[1], nodes[2], 100000);

	let mut payments = Vec::new();
	for _ in 0..50 {
		let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[2], 100000);
		nodes[1].node.send_payment_with_route(route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		payments.push((payment_preimage, payment_hash));
	}
	check_added_monitors!(nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let initial_payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(initial_payment_event.node_id, node_c_id);

	// There is now one HTLC in an outbound commitment transaction and (OUR_MAX_HTLCS - 1) HTLCs in
	// the holding cell waiting on B's RAA to send. At this point we should not be able to add
	// another HTLC.
	{
		unwrap_send_err!(nodes[1], nodes[1].node.send_payment_with_route(route, payment_hash_1,
				RecipientOnionFields::secret_only(payment_secret_1), PaymentId(payment_hash_1.0)
			), true, APIError::ChannelUnavailable { .. }, {});
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	// This should also be true if we try to forward a payment.
	let (route, payment_hash_2, _, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[2], 100000);
	{
		nodes[0].node.send_payment_with_route(route, payment_hash_2,
			RecipientOnionFields::secret_only(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
	// fails), the second will process the resulting failure and fail the HTLC backward.
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }]);
	check_added_monitors!(nodes[1], 1);

	let bs_fail_updates = get_htlc_update_msgs!(nodes[1], node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_fail_updates.commitment_signed, false, true);

	expect_payment_failed_with_update!(nodes[0], payment_hash_2, false, chan_2.0.contents.short_channel_id, false);

	// Now forward all the pending HTLCs and claim them back
	nodes[2].node.handle_update_add_htlc(node_b_id, &initial_payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &initial_payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);

	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	let as_updates = get_htlc_update_msgs!(nodes[1], node_c_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);

	for ref update in as_updates.update_add_htlcs.iter() {
		nodes[2].node.handle_update_add_htlc(node_b_id, update);
	}
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &as_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_raa);
	check_added_monitors!(nodes[2], 1);
	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_final_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);

	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_final_raa);
	check_added_monitors!(nodes[2], 1);

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), payments.len());
	for (event, &(_, ref hash)) in events.iter().zip(payments.iter()) {
		match event {
			&Event::PaymentClaimable { ref payment_hash, .. } => {
				assert_eq!(*payment_hash, *hash);
			},
			_ => panic!("Unexpected event"),
		};
	}

	for (preimage, _) in payments.drain(..) {
		claim_payment(&nodes[1], &[&nodes[2]], preimage);
	}

	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_basic_channel_reserve() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;

	// The 2* and +1 are for the fee spike reserve.
	let commit_tx_fee = 2 * commit_tx_fee_msat(get_feerate!(nodes[0], nodes[1], chan.2), 1 + 1, &get_channel_type_features!(nodes[0], nodes[1], chan.2));
	let max_can_send = 5000000 - channel_reserve - commit_tx_fee;
	let (mut route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], max_can_send);
	route.paths[0].hops.last_mut().unwrap().fee_msat += 1;
	let err = nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0));
	unwrap_send_err!(nodes[0], err, true, APIError::ChannelUnavailable { .. }, {}	);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	send_payment(&nodes[0], &vec![&nodes[1]], max_can_send);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_fee_spike_violation_fails_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 3460000);
	route.paths[0].hops[0].fee_msat += 1;
	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).expect("RNG is bad!");

	let cur_height = nodes[1].node.best_block.read().unwrap().height + 1;

	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv);
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0],
		3460001, &recipient_onion_fields, cur_height, &None, None, None).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 0,
		amount_msat: htlc_msat,
		payment_hash: payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
		skimmed_fee_msat: None,
		blinding_point: None,
	};

	nodes[1].node.handle_update_add_htlc(node_a_id, &msg);

	// Now manually create the commitment_signed message corresponding to the update_add
	// nodes[0] just sent. In the code for construction of this message, "local" refers
	// to the sender of the message, and "remote" refers to the receiver.

	let feerate_per_kw = get_feerate!(nodes[0], nodes[1], chan.2);

	const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

	let (local_secret, next_local_point) = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		let local_chan = chan_lock.channel_by_id.get(&chan.2).and_then(Channel::as_funded).unwrap();
		let chan_signer = local_chan.get_signer();
		// Make the signer believe we validated another commitment, so we can release the secret
		chan_signer.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;

		 (chan_signer.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER).unwrap(),
		 chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 2, &secp_ctx).unwrap())
	};
	let remote_point = {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_a_id).unwrap().lock().unwrap();
		let remote_chan = chan_lock.channel_by_id.get(&chan.2).and_then(Channel::as_funded).unwrap();
		let chan_signer = remote_chan.get_signer();
		chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, &secp_ctx).unwrap()
	};

	// Build the remote commitment transaction so we can sign it, and then later use the
	// signature for the commitment_signed message.
	let local_chan_balance = 1313;

	let accepted_htlc_info = chan_utils::HTLCOutputInCommitment {
		offered: false,
		amount_msat: 3460001,
		cltv_expiry: htlc_cltv,
		payment_hash,
		transaction_output_index: Some(1),
	};

	let commitment_number = INITIAL_COMMITMENT_NUMBER - 1;

	let res = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let local_chan_lock = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		let local_chan = local_chan_lock.channel_by_id.get(&chan.2).and_then(Channel::as_funded).unwrap();
		let local_chan_signer = local_chan.get_signer();
		let commitment_tx = CommitmentTransaction::new(
			commitment_number,
			&remote_point,
			95000,
			local_chan_balance,
			feerate_per_kw,
			vec![accepted_htlc_info],
			&local_chan.funding.channel_transaction_parameters.as_counterparty_broadcastable(),
			&secp_ctx,
		);
		local_chan_signer.as_ecdsa().unwrap().sign_counterparty_commitment(
			&local_chan.funding.channel_transaction_parameters, &commitment_tx, Vec::new(),
			Vec::new(), &secp_ctx,
		).unwrap()
	};

	let commit_signed_msg = msgs::CommitmentSigned {
		channel_id: chan.2,
		signature: res.0,
		htlc_signatures: res.1,
		batch: None,
		#[cfg(taproot)]
		partial_signature_with_nonce: None,
	};

	// Send the commitment_signed message to the nodes[1].
	nodes[1].node.handle_commitment_signed(node_a_id, &commit_signed_msg);
	let _ = nodes[1].node.get_and_clear_pending_msg_events();

	// Send the RAA to nodes[1].
	let raa_msg = msgs::RevokeAndACK {
		channel_id: chan.2,
		per_commitment_secret: local_secret,
		next_per_commitment_point: next_local_point,
		#[cfg(taproot)]
		next_local_nonce: None,
	};
	nodes[1].node.handle_revoke_and_ack(node_a_id, &raa_msg);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_htlc_handling_failed_destinations!(nodes[1].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	// Make sure the HTLC failed in the way we expect.
	match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fail_htlcs, .. }, .. } => {
			assert_eq!(update_fail_htlcs.len(), 1);
			update_fail_htlcs[0].clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].logger.assert_log("lightning::ln::channel",
		format!("Attempting to fail HTLC due to fee spike buffer violation in channel {}. Rebalancing is required.", raa_msg.channel_id), 1);

	check_added_monitors!(nodes[1], 3);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_chan_reserve_violation_outbound_htlc_inbound_chan() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// Set the fee rate for the channel very high, to the point where the fundee
	// sending any above-dust amount would result in a channel reserve violation.
	// In this test we check that we would be prevented from sending an HTLC in
	// this situation.
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let default_config = UserConfig::default();
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	let mut push_amt = 100_000_000;
	push_amt -= commit_tx_fee_msat(feerate_per_kw, MIN_AFFORDABLE_HTLC_COUNT as u64, &channel_type_features);

	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;

	let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, push_amt);

	// Fetch a route in advance as we will be unable to once we're unable to send.
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 1_000_000);
	// Sending exactly enough to hit the reserve amount should be accepted
	for _ in 0..MIN_AFFORDABLE_HTLC_COUNT {
		route_payment(&nodes[1], &[&nodes[0]], 1_000_000);
	}

	// However one more HTLC should be significantly over the reserve amount and fail.
	unwrap_send_err!(nodes[1], nodes[1].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_chan_reserve_violation_inbound_htlc_outbound_channel() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let default_config = UserConfig::default();
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	// Set nodes[0]'s balance such that they will consider any above-dust received HTLC to be a
	// channel reserve violation (so their balance is channel reserve (1000 sats) + commitment
	// transaction fee with 0 HTLCs (183 sats)).
	let mut push_amt = 100_000_000;
	push_amt -= commit_tx_fee_msat(feerate_per_kw, MIN_AFFORDABLE_HTLC_COUNT as u64, &channel_type_features);
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, push_amt);

	// Send four HTLCs to cover the initial push_msat buffer we're required to include
	for _ in 0..MIN_AFFORDABLE_HTLC_COUNT {
		route_payment(&nodes[1], &[&nodes[0]], 1_000_000);
	}

	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 1000);
	route.paths[0].hops[0].fee_msat = 700_000;
	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
	let cur_height = nodes[1].node.best_block.read().unwrap().height + 1;
	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv);
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0],
		700_000, &recipient_onion_fields, cur_height, &None, None, None).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: MIN_AFFORDABLE_HTLC_COUNT as u64,
		amount_msat: htlc_msat,
		payment_hash: payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
		skimmed_fee_msat: None,
		blinding_point: None,
	};

	nodes[0].node.handle_update_add_htlc(node_b_id, &msg);
	// Check that the payment failed and the channel is closed in response to the malicious UpdateAdd.
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager", "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value", 3);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value");
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value".to_string() },
		[node_b_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_chan_reserve_dust_inbound_htlcs_outbound_chan() {
	// Test that if we receive many dust HTLCs over an outbound channel, they don't count when
	// calculating our commitment transaction fee (this was previously broken).
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let default_config = UserConfig::default();
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	// Set nodes[0]'s balance such that they will consider any above-dust received HTLC to be a
	// channel reserve violation (so their balance is channel reserve (1000 sats) + commitment
	// transaction fee with 0 HTLCs (183 sats)).
	let mut push_amt = 100_000_000;
	push_amt -= commit_tx_fee_msat(feerate_per_kw, MIN_AFFORDABLE_HTLC_COUNT as u64, &channel_type_features);
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, push_amt);

	let dust_amt = crate::ln::channel::MIN_CHAN_DUST_LIMIT_SATOSHIS * 1000
		+ feerate_per_kw as u64 * htlc_success_tx_weight(&channel_type_features) / 1000 * 1000 - 1;
	// In the previous code, routing this dust payment would cause nodes[0] to perceive a channel
	// reserve violation even though it's a dust HTLC and therefore shouldn't count towards the
	// commitment transaction fee.
	route_payment(&nodes[1], &[&nodes[0]], dust_amt);

	// Send four HTLCs to cover the initial push_msat buffer we're required to include
	for _ in 0..MIN_AFFORDABLE_HTLC_COUNT {
		route_payment(&nodes[1], &[&nodes[0]], 1_000_000);
	}

	// One more than the dust amt should fail, however.
	let (mut route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], dust_amt);
	route.paths[0].hops[0].fee_msat += 1;
	unwrap_send_err!(nodes[1], nodes[1].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
}
