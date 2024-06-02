use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use crate::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::{self, inbound_payment, PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::channelmanager::{HTLCForwardInfo, PaymentId, RecipientOnionFields};
use crate::ln::onion_payment::create_recv_pending_htlc_info;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{self};
use crate::ln::msgs::ChannelMessageHandler;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters, find_route};
use crate::util::ser::Writeable;
use crate::util::test_utils;
use crate::sign::{EntropySource, NodeSigner};

#[test]
fn test_keysend_dup_hash_partial_mpp() {
	// Test that a keysend payment with a duplicate hash to an existing partial MPP payment fails as
	// expected.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// First, send a partial MPP payment.
	let (route, our_payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100_000);
	let mut mpp_route = route.clone();
	mpp_route.paths.push(mpp_route.paths[0].clone());

	let payment_id = PaymentId([42; 32]);
	// Use the utility function send_payment_along_path to send the payment with MPP data which
	// indicates there are more HTLCs coming.
	let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
	let session_privs = nodes[0].node.test_add_new_pending_payment(our_payment_hash,
		RecipientOnionFields::secret_only(payment_secret), payment_id, &mpp_route).unwrap();
	nodes[0].node.test_send_payment_along_path(&mpp_route.paths[0], &our_payment_hash,
		RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[0]).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);

	// Next, send a keysend payment with the same payment_hash and make sure it fails.
	nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
		RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = events.drain(..).next().unwrap();
	let payment_event = SendEvent::from_event(ev);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
	expect_payment_failed!(nodes[0], our_payment_hash, true);

	// Send the second half of the original MPP payment.
	nodes[0].node.test_send_payment_along_path(&mpp_route.paths[1], &our_payment_hash,
		RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[1]).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), true, None);

	// Claim the full MPP payment. Note that we can't use a test utility like
	// claim_funds_along_route because the ordering of the messages causes the second half of the
	// payment to be put in the holding cell, which confuses the test utilities. So we exchange the
	// lightning messages manually.
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], our_payment_hash, 200_000);
	check_added_monitors!(nodes[1], 2);

	let bs_first_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_first_updates.update_fulfill_htlcs[0]);
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (as_first_raa, as_first_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_second_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_first_cs);
	check_added_monitors!(nodes[1], 1);
	let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_second_updates.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
	let as_second_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
	check_added_monitors!(nodes[0], 1);

	// Note that successful MPP payments will generate a single PaymentSent event upon the first
	// path's success and a PaymentPathSuccessful event for each path's success.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path } => {
			assert_eq!(payment_id, *actual_payment_id);
			assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
			assert_eq!(route.paths[0], *path);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path } => {
			assert_eq!(payment_id, *actual_payment_id);
			assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
			assert_eq!(route.paths[0], *path);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_keysend_dup_payment_hash() {
	do_test_keysend_dup_payment_hash(false);
	do_test_keysend_dup_payment_hash(true);
}

fn do_test_keysend_dup_payment_hash(accept_mpp_keysend: bool) {
	// (1): Test that a keysend payment with a duplicate payment hash to an existing pending
	//      outbound regular payment fails as expected.
	// (2): Test that a regular payment with a duplicate payment hash to an existing keysend payment
	//      fails as expected.
	// (3): Test that a keysend payment with a duplicate payment hash to an existing keysend
	//      payment fails as expected. When `accept_mpp_keysend` is false, this tests that we
	//      reject MPP keysend payments, since in this case where the payment has no payment
	//      secret, a keysend payment with a duplicate hash is basically an MPP keysend. If
	//      `accept_mpp_keysend` is true, this tests that we only accept MPP keysends with
	//      payment secrets and reject otherwise.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut mpp_keysend_cfg = test_default_channel_config();
	mpp_keysend_cfg.accept_mpp_keysend = accept_mpp_keysend;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(mpp_keysend_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();

	// To start (1), send a regular payment but don't claim it.
	let expected_route = [&nodes[1]];
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &expected_route, 100_000);

	// Next, attempt a keysend payment and make sure it fails.
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id(),
		TEST_FINAL_CLTV, false), 100_000);
	let route = find_route(
		&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
		None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
	).unwrap();
	nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
		RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = events.drain(..).next().unwrap();
	let payment_event = SendEvent::from_event(ev);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
	// fails), the second will process the resulting failure and fail the HTLC backward
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
	expect_payment_failed!(nodes[0], payment_hash, true);

	// Finally, claim the original payment.
	claim_payment(&nodes[0], &expected_route, payment_preimage);

	// To start (2), send a keysend payment but don't claim it.
	let payment_preimage = PaymentPreimage([42; 32]);
	let route = find_route(
		&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
		None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
	).unwrap();
	let payment_hash = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
		RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path = vec![&nodes[1]];
	pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

	// Next, attempt a regular payment and make sure it fails.
	let payment_secret = PaymentSecret([43; 32]);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = events.drain(..).next().unwrap();
	let payment_event = SendEvent::from_event(ev);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
	expect_payment_failed!(nodes[0], payment_hash, true);

	// Finally, succeed the keysend payment.
	claim_payment(&nodes[0], &expected_route, payment_preimage);

	// To start (3), send a keysend payment but don't claim it.
	let payment_id_1 = PaymentId([44; 32]);
	let payment_hash = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
		RecipientOnionFields::spontaneous_empty(), payment_id_1).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path = vec![&nodes[1]];
	pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

	// Next, attempt a keysend payment and make sure it fails.
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id(), TEST_FINAL_CLTV, false),
		100_000
	);
	let route = find_route(
		&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
		None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
	).unwrap();
	let payment_id_2 = PaymentId([45; 32]);
	nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
		RecipientOnionFields::spontaneous_empty(), payment_id_2).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = events.drain(..).next().unwrap();
	let payment_event = SendEvent::from_event(ev);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
	expect_payment_failed!(nodes[0], payment_hash, true);

	// Finally, claim the original payment.
	claim_payment(&nodes[0], &expected_route, payment_preimage);
}

#[test]
fn test_keysend_hash_mismatch() {
	// Test that if we receive a keysend `update_add_htlc` msg, we fail as expected if the keysend
	// preimage doesn't match the msg's payment hash.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let payer_pubkey = nodes[0].node.get_our_node_id();
	let payee_pubkey = nodes[1].node.get_our_node_id();

	let _chan = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(payee_pubkey, 40, false), 10_000);
	let network_graph = nodes[0].network_graph;
	let first_hops = nodes[0].node.list_usable_channels();
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let route = find_route(
		&payer_pubkey, &route_params, &network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
		nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
	).unwrap();

	let test_preimage = PaymentPreimage([42; 32]);
	let mismatch_payment_hash = PaymentHash([43; 32]);
	let session_privs = nodes[0].node.test_add_new_pending_payment(mismatch_payment_hash,
		RecipientOnionFields::spontaneous_empty(), PaymentId(mismatch_payment_hash.0), &route).unwrap();
	nodes[0].node.test_send_payment_internal(&route, mismatch_payment_hash,
		RecipientOnionFields::spontaneous_empty(), Some(test_preimage), PaymentId(mismatch_payment_hash.0), None, session_privs).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Payment preimage didn't match payment hash", 1);
}

#[test]
fn test_keysend_msg_with_secret_err() {
	// Test that we error as expected if we receive a keysend payment that includes a payment
	// secret when we don't support MPP keysend.
	let mut reject_mpp_keysend_cfg = test_default_channel_config();
	reject_mpp_keysend_cfg.accept_mpp_keysend = false;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(reject_mpp_keysend_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let payer_pubkey = nodes[0].node.get_our_node_id();
	let payee_pubkey = nodes[1].node.get_our_node_id();

	let _chan = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(payee_pubkey, 40, false), 10_000);
	let network_graph = nodes[0].network_graph;
	let first_hops = nodes[0].node.list_usable_channels();
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let route = find_route(
		&payer_pubkey, &route_params, &network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
		nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
	).unwrap();

	let test_preimage = PaymentPreimage([42; 32]);
	let test_secret = PaymentSecret([43; 32]);
	let payment_hash = PaymentHash(Sha256::hash(&test_preimage.0).to_byte_array());
	let session_privs = nodes[0].node.test_add_new_pending_payment(payment_hash,
		RecipientOnionFields::secret_only(test_secret), PaymentId(payment_hash.0), &route).unwrap();
	nodes[0].node.test_send_payment_internal(&route, payment_hash,
		RecipientOnionFields::secret_only(test_secret), Some(test_preimage),
		PaymentId(payment_hash.0), None, session_privs).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "We don't support MPP keysend payments", 1);
}

#[test]
fn bad_inbound_payment_hash() {
	// Add coverage for checking that a user-provided payment hash matches the payment secret.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let highest_seen_timestamp = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet).header.time;
	let node_signer = node_cfgs[0].keys_manager;
	let inbound_pmt_key_material = node_signer.get_inbound_payment_key_material();
	let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);

	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(&nodes[0]);
	let payment_data = msgs::FinalOnionHopData {
		payment_secret,
		total_msat: 100_000,
	};

	// Ensure that if the payment hash given to `inbound_payment::verify` differs from the original,
	// payment verification fails as expected.
	let mut bad_payment_hash = payment_hash.clone();
	bad_payment_hash.0[0] += 1;
	match inbound_payment::verify(bad_payment_hash, &payment_data, highest_seen_timestamp as u64, &expanded_inbound_key, &nodes[0].logger) {
		Ok(_) => panic!("Unexpected ok"),
		Err(()) => {
			nodes[0].logger.assert_log_contains("lightning::ln::inbound_payment", "Failing HTLC with user-generated payment_hash", 1);
		}
	}

	// Check that using the original payment hash succeeds.
	assert!(inbound_payment::verify(payment_hash, &payment_data, highest_seen_timestamp as u64, &expanded_inbound_key, &nodes[0].logger).is_ok());
}

#[test]
fn reject_excessively_underpaying_htlcs() {
	let chanmon_cfg = create_chanmon_cfgs(1);
	let node_cfg = create_node_cfgs(1, &chanmon_cfg);
	let user_cfg = test_default_channel_config();
	let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[Some(user_cfg)]);
	let node = create_network(1, &node_cfg, &node_chanmgr);
	let sender_intended_amt_msat = 100;
	let extra_fee_msat = 10;
	let hop_data = msgs::InboundOnionPayload::Receive {
		sender_intended_htlc_amt_msat: 100,
		cltv_expiry_height: 42,
		payment_metadata: None,
		keysend_preimage: None,
		payment_data: Some(msgs::FinalOnionHopData {
			payment_secret: PaymentSecret([0; 32]), total_msat: sender_intended_amt_msat,
		}),
		custom_tlvs: Vec::new(),
	};
	// Check that if the amount we received + the penultimate hop extra fee is less than the sender
	// intended amount, we fail the payment.
	let current_height: u32 = node[0].node.best_block.read().unwrap().height;
	if let Err(ln::onion_payment::InboundHTLCErr { err_code, .. }) =
		create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
			sender_intended_amt_msat - extra_fee_msat - 1, 42, None, true, Some(extra_fee_msat),
			current_height, user_cfg.accept_mpp_keysend)
	{
		assert_eq!(err_code, 19);
	} else { panic!(); }

	// If amt_received + extra_fee is equal to the sender intended amount, we're fine.
	let hop_data = msgs::InboundOnionPayload::Receive { // This is the same payload as above, InboundOnionPayload doesn't implement Clone
		sender_intended_htlc_amt_msat: 100,
		cltv_expiry_height: 42,
		payment_metadata: None,
		keysend_preimage: None,
		payment_data: Some(msgs::FinalOnionHopData {
			payment_secret: PaymentSecret([0; 32]), total_msat: sender_intended_amt_msat,
		}),
		custom_tlvs: Vec::new(),
	};
	let current_height: u32 = node[0].node.best_block.read().unwrap().height;
	assert!(create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
		sender_intended_amt_msat - extra_fee_msat, 42, None, true, Some(extra_fee_msat),
		current_height, user_cfg.accept_mpp_keysend).is_ok());
}

#[test]
fn test_final_incorrect_cltv(){
	let chanmon_cfg = create_chanmon_cfgs(1);
	let node_cfg = create_node_cfgs(1, &chanmon_cfg);
	let user_cfg = test_default_channel_config();
	let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[Some(user_cfg)]);
	let node = create_network(1, &node_cfg, &node_chanmgr);

	let current_height: u32 = node[0].node.best_block.read().unwrap().height;
	let result = create_recv_pending_htlc_info(msgs::InboundOnionPayload::Receive {
		sender_intended_htlc_amt_msat: 100,
		cltv_expiry_height: 22,
		payment_metadata: None,
		keysend_preimage: None,
		payment_data: Some(msgs::FinalOnionHopData {
			payment_secret: PaymentSecret([0; 32]), total_msat: 100,
		}),
		custom_tlvs: Vec::new(),
	}, [0; 32], PaymentHash([0; 32]), 100, 23, None, true, None, current_height,
		user_cfg.accept_mpp_keysend);

	// Should not return an error as this condition:
	// https://github.com/lightning/bolts/blob/4dcc377209509b13cf89a4b91fde7d478f5b46d8/04-onion-routing.md?plain=1#L334
	// is not satisfied.
	assert!(result.is_ok());
}

#[test]
fn test_payment_display() {
	let payment_id = PaymentId([42; 32]);
	assert_eq!(format!("{}", &payment_id), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
	let payment_hash = PaymentHash([42; 32]);
	assert_eq!(format!("{}", &payment_hash), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
	let payment_preimage = PaymentPreimage([42; 32]);
	assert_eq!(format!("{}", &payment_preimage), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
}

#[test]
fn test_malformed_forward_htlcs_ser() {
	// Ensure that `HTLCForwardInfo::FailMalformedHTLC`s are (de)serialized properly.
	let chanmon_cfg = create_chanmon_cfgs(1);
	let node_cfg = create_node_cfgs(1, &chanmon_cfg);
	let persister;
	let chain_monitor;
	let chanmgrs = create_node_chanmgrs(1, &node_cfg, &[None]);
	let deserialized_chanmgr;
	let mut nodes = create_network(1, &node_cfg, &chanmgrs);

	let dummy_failed_htlc = |htlc_id| {
		HTLCForwardInfo::FailHTLC { htlc_id, err_packet: msgs::OnionErrorPacket { data: vec![42] }, }
	};
	let dummy_malformed_htlc = |htlc_id| {
		HTLCForwardInfo::FailMalformedHTLC { htlc_id, failure_code: 0x4000, sha256_of_onion: [0; 32] }
	};

	let dummy_htlcs_1: Vec<HTLCForwardInfo> = (1..10).map(|htlc_id| {
		if htlc_id % 2 == 0 {
			dummy_failed_htlc(htlc_id)
		} else {
			dummy_malformed_htlc(htlc_id)
		}
	}).collect();

	let dummy_htlcs_2: Vec<HTLCForwardInfo> = (1..10).map(|htlc_id| {
		if htlc_id % 2 == 1 {
			dummy_failed_htlc(htlc_id)
		} else {
			dummy_malformed_htlc(htlc_id)
		}
	}).collect();


	let (scid_1, scid_2) = (42, 43);
	let mut forward_htlcs = new_hash_map();
	forward_htlcs.insert(scid_1, dummy_htlcs_1.clone());
	forward_htlcs.insert(scid_2, dummy_htlcs_2.clone());

	let mut chanmgr_fwd_htlcs = nodes[0].node.forward_htlcs.lock().unwrap();
	*chanmgr_fwd_htlcs = forward_htlcs.clone();
	core::mem::drop(chanmgr_fwd_htlcs);

	reload_node!(nodes[0], nodes[0].node.encode(), &[], persister, chain_monitor, deserialized_chanmgr);

	let mut deserialized_fwd_htlcs = nodes[0].node.forward_htlcs.lock().unwrap();
	for scid in [scid_1, scid_2].iter() {
		let deserialized_htlcs = deserialized_fwd_htlcs.remove(scid).unwrap();
		assert_eq!(forward_htlcs.remove(scid).unwrap(), deserialized_htlcs);
	}
	assert!(deserialized_fwd_htlcs.is_empty());
	core::mem::drop(deserialized_fwd_htlcs);

	expect_pending_htlcs_forwardable!(nodes[0]);
}
