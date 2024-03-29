use bitcoin::hashes::Hash;
use crate::ln::channelmanager::{PaymentId, PaymentSendFailure, RecipientOnionFields};
use crate::ln::functional_test_utils::*;
use crate::util::errors::APIError;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
use crate::ln::channelmanager;
use crate::ln::ChannelId;
use crate::ln::msgs::{self};
use crate::ln::msgs::ChannelMessageHandler;
use crate::prelude::*;
use crate::util::config::ChannelConfig;
use crate::sign::EntropySource;


#[test]
fn test_notify_limits() {
	// Check that a few cases which don't require the persistence of a new ChannelManager,
	// indeed, do not cause the persistence of a new ChannelManager.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// All nodes start with a persistable update pending as `create_network` connects each node
	// with all other nodes to make most tests simpler.
	assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());

	let mut chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// We check that the channel info nodes have doesn't change too early, even though we try
	// to connect messages with new values
	chan.0.contents.fee_base_msat *= 2;
	chan.1.contents.fee_base_msat *= 2;
	let node_a_chan_info = nodes[0].node.list_channels_with_counterparty(
		&nodes[1].node.get_our_node_id()).pop().unwrap();
	let node_b_chan_info = nodes[1].node.list_channels_with_counterparty(
		&nodes[0].node.get_our_node_id()).pop().unwrap();

	// The first two nodes (which opened a channel) should now require fresh persistence
	assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
	// ... but the last node should not.
	assert!(!nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());
	// After persisting the first two nodes they should no longer need fresh persistence.
	assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());

	// Node 3, unrelated to the only channel, shouldn't care if it receives a channel_update
	// about the channel.
	nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.0);
	nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.1);
	assert!(!nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());

	// The nodes which are a party to the channel should also ignore messages from unrelated
	// parties.
	nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
	nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
	nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
	nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
	assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());

	// At this point the channel info given by peers should still be the same.
	assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
	assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

	// An earlier version of handle_channel_update didn't check the directionality of the
	// update message and would always update the local fee info, even if our peer was
	// (spuriously) forwarding us our own channel_update.
	let as_node_one = nodes[0].node.get_our_node_id().serialize()[..] < nodes[1].node.get_our_node_id().serialize()[..];
	let as_update = if as_node_one == (chan.0.contents.flags & 1 == 0 /* chan.0 is from node one */) { &chan.0 } else { &chan.1 };
	let bs_update = if as_node_one == (chan.0.contents.flags & 1 == 0 /* chan.0 is from node one */) { &chan.1 } else { &chan.0 };

	// First deliver each peers' own message, checking that the node doesn't need to be
	// persisted and that its channel info remains the same.
	nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &as_update);
	nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &bs_update);
	assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
	assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

	// Finally, deliver the other peers' message, ensuring each node needs to be persisted and
	// the channel info has updated.
	nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &bs_update);
	nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &as_update);
	assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
	assert_ne!(nodes[0].node.list_channels()[0], node_a_chan_info);
	assert_ne!(nodes[1].node.list_channels()[0], node_b_chan_info);
}

#[test]
fn test_drop_disconnected_peers_when_removing_channels() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[1].node.get_our_node_id()).unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);

	{
		// Assert that nodes[1] is awaiting removal for nodes[0] once nodes[1] has been
		// disconnected and the channel between has been force closed.
		let nodes_0_per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		// Assert that nodes[1] isn't removed before `timer_tick_occurred` has been executed.
		assert_eq!(nodes_0_per_peer_state.len(), 1);
		assert!(nodes_0_per_peer_state.get(&nodes[1].node.get_our_node_id()).is_some());
	}

	nodes[0].node.timer_tick_occurred();

	{
		// Assert that nodes[1] has now been removed.
		assert_eq!(nodes[0].node.per_peer_state.read().unwrap().len(), 0);
	}
}

#[test]
fn test_outpoint_to_peer_coverage() {
	// Test that the `ChannelManager:outpoint_to_peer` contains channels which have been assigned
	// a `channel_id` (i.e. have had the funding tx created), and that they are removed once
	// the channel is successfully closed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 500_000_000, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);
	let channel_id = ChannelId::from_bytes(tx.txid().to_byte_array());
	{
		// Ensure that the `outpoint_to_peer` map is empty until either party has received the
		// funding transaction, and have the real `channel_id`.
		assert_eq!(nodes[0].node.outpoint_to_peer.lock().unwrap().len(), 0);
		assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);
	}

	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	{
		// Assert that `nodes[0]`'s `outpoint_to_peer` map is populated with the channel as soon as
		// as it has the funding transaction.
		let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_0_lock.len(), 1);
		assert!(nodes_0_lock.contains_key(&funding_output));
	}

	assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);

	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	{
		let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_0_lock.len(), 1);
		assert!(nodes_0_lock.contains_key(&funding_output));
	}
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	{
		// Assert that `nodes[1]`'s `outpoint_to_peer` map is populated with the channel as
		// soon as it has the funding transaction.
		let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_1_lock.len(), 1);
		assert!(nodes_1_lock.contains_key(&funding_output));
	}
	check_added_monitors!(nodes[1], 1);
	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	check_added_monitors!(nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
	let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, nodes_0_update, nodes_1_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &nodes_0_update, &nodes_1_update);

	nodes[0].node.close_channel(&channel_id, &nodes[1].node.get_our_node_id()).unwrap();
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id()));
	let nodes_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &nodes_1_shutdown);

	let closing_signed_node_0 = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0);
	{
		// Assert that the channel is kept in the `outpoint_to_peer` map for both nodes until the
		// channel can be fully closed by both parties (i.e. no outstanding htlcs exists, the
		// fee for the closing transaction has been negotiated and the parties has the other
		// party's signature for the fee negotiated closing transaction.)
		let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_0_lock.len(), 1);
		assert!(nodes_0_lock.contains_key(&funding_output));
	}

	{
		// At this stage, `nodes[1]` has proposed a fee for the closing transaction in the
		// `handle_closing_signed` call above. As `nodes[1]` has not yet received the signature
		// from `nodes[0]` for the closing transaction with the proposed fee, the channel is
		// kept in the `nodes[1]`'s `outpoint_to_peer` map.
		let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_1_lock.len(), 1);
		assert!(nodes_1_lock.contains_key(&funding_output));
	}

	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id()));
	{
		// `nodes[0]` accepts `nodes[1]`'s proposed fee for the closing transaction, and
		// therefore has all it needs to fully close the channel (both signatures for the
		// closing transaction).
		// Assert that the channel is removed from `nodes[0]`'s `outpoint_to_peer` map as it can be
		// fully closed by `nodes[0]`.
		assert_eq!(nodes[0].node.outpoint_to_peer.lock().unwrap().len(), 0);

		// Assert that the channel is still in `nodes[1]`'s  `outpoint_to_peer` map, as `nodes[1]`
		// doesn't have `nodes[0]`'s signature for the closing transaction yet.
		let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
		assert_eq!(nodes_1_lock.len(), 1);
		assert!(nodes_1_lock.contains_key(&funding_output));
	}

	let (_nodes_0_update, closing_signed_node_0) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0.unwrap());
	{
		// Assert that the channel has now been removed from both parties `outpoint_to_peer` map once
		// they both have everything required to fully close the channel.
		assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);
	}
	let (_nodes_1_update, _none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());

	check_closed_event!(nodes[0], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 1000000);
	check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 1000000);
}


fn check_not_connected_to_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
	let expected_message = format!("Not connected to node: {}", expected_public_key);
	check_api_error_message(expected_message, res_err)
}

fn check_unkown_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
	let expected_message = format!("Can't find a peer matching the passed counterparty node_id {}", expected_public_key);
	check_api_error_message(expected_message, res_err)
}

fn check_channel_unavailable_error<T>(res_err: Result<T, APIError>, expected_channel_id: ChannelId, peer_node_id: PublicKey) {
	let expected_message = format!("Channel with id {} not found for the passed counterparty node_id {}", expected_channel_id, peer_node_id);
	check_api_error_message(expected_message, res_err)
}

fn check_api_misuse_error<T>(res_err: Result<T, APIError>) {
	let expected_message = "No such channel awaiting to be accepted.".to_string();
	check_api_error_message(expected_message, res_err)
}

fn check_api_error_message<T>(expected_err_message: String, res_err: Result<T, APIError>) {
	match res_err {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(err, expected_err_message);
		},
		Err(APIError::ChannelUnavailable { err }) => {
			assert_eq!(err, expected_err_message);
		},
		Ok(_) => panic!("Unexpected Ok"),
		Err(_) => panic!("Unexpected Error"),
	}
}

#[test]
fn test_api_calls_with_unkown_counterparty_node() {
	// Tests that our API functions that expects a `counterparty_node_id` as input, behaves as
	// expected if the `counterparty_node_id` is an unkown peer in the
	// `ChannelManager::per_peer_state` map.
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);

	// Dummy values
	let channel_id = ChannelId::from_bytes([4; 32]);
	let unkown_public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &SecretKey::from_slice(&[42; 32]).unwrap());
	let intercept_id = super::InterceptId([0; 32]);

	// Test the API functions.
	check_not_connected_to_peer_error(nodes[0].node.create_channel(unkown_public_key, 1_000_000, 500_000_000, 42, None, None), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.accept_inbound_channel(&channel_id, &unkown_public_key, 42), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.close_channel(&channel_id, &unkown_public_key), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &unkown_public_key), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.force_close_without_broadcasting_txn(&channel_id, &unkown_public_key), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.forward_intercepted_htlc(intercept_id, &channel_id, unkown_public_key, 1_000_000), unkown_public_key);

	check_unkown_peer_error(nodes[0].node.update_channel_config(&unkown_public_key, &[channel_id], &ChannelConfig::default()), unkown_public_key);
}

#[test]
fn test_api_calls_with_unavailable_channel() {
	// Tests that our API functions that expects a `counterparty_node_id` and a `channel_id`
	// as input, behaves as expected if the `counterparty_node_id` is a known peer in the
	// `ChannelManager::per_peer_state` map, but the peer state doesn't contain a channel with
	// the given `channel_id`.
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);

	let counterparty_node_id = nodes[1].node.get_our_node_id();

	// Dummy values
	let channel_id = ChannelId::from_bytes([4; 32]);

	// Test the API functions.
	check_api_misuse_error(nodes[0].node.accept_inbound_channel(&channel_id, &counterparty_node_id, 42));

	check_channel_unavailable_error(nodes[0].node.close_channel(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

	check_channel_unavailable_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

	check_channel_unavailable_error(nodes[0].node.force_close_without_broadcasting_txn(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

	check_channel_unavailable_error(nodes[0].node.forward_intercepted_htlc(channelmanager::InterceptId([0; 32]), &channel_id, counterparty_node_id, 1_000_000), channel_id, counterparty_node_id);

	check_channel_unavailable_error(nodes[0].node.update_channel_config(&counterparty_node_id, &[channel_id], &ChannelConfig::default()), channel_id, counterparty_node_id);
}

#[test]
fn test_connection_limiting() {
	// Test that we limit un-channel'd peers and un-funded channels properly.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Note that create_network connects the nodes together for us

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	let mut funding_tx = None;
	for idx in 0..channelmanager::MAX_UNFUNDED_CHANS_PER_PEER {
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

		if idx == 0 {
			nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);
			let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);
			funding_tx = Some(tx.clone());
			nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx).unwrap();
			let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

			nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
			check_added_monitors!(nodes[1], 1);
			expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

			let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

			nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
			check_added_monitors!(nodes[0], 1);
			expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
		}
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}

	// A MAX_UNFUNDED_CHANS_PER_PEER + 1 channel will be summarily rejected
	open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(
		&nodes[0].keys_manager);
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);

	// Further, because all of our channels with nodes[0] are inbound, and none of them funded,
	// it doesn't count as a "protected" peer, i.e. it counts towards the MAX_NO_CHANNEL_PEERS
	// limit.
	let mut peer_pks = Vec::with_capacity(channelmanager::MAX_NO_CHANNEL_PEERS);
	for _ in 1..channelmanager::MAX_NO_CHANNEL_PEERS {
		let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		peer_pks.push(random_pk);
		nodes[1].node.peer_connected(&random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
	}
	let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
		&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
	nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap_err();

	// Also importantly, because nodes[0] isn't "protected", we will refuse a reconnection from
	// them if we have too many un-channel'd peers.
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	let chan_closed_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(chan_closed_events.len(), channelmanager::MAX_UNFUNDED_CHANS_PER_PEER - 1);
	for ev in chan_closed_events {
		if let Event::ChannelClosed { .. } = ev { } else { panic!(); }
	}
	nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap_err();

	// but of course if the connection is outbound its allowed...
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	// Now nodes[0] is disconnected but still has a pending, un-funded channel lying around.
	// Even though we accept one more connection from new peers, we won't actually let them
	// open channels.
	assert!(peer_pks.len() > channelmanager::MAX_UNFUNDED_CHANNEL_PEERS - 1);
	for i in 0..channelmanager::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
		nodes[1].node.handle_open_channel(&peer_pks[i], &open_channel_msg);
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, peer_pks[i]);
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}
	nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
	assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);

	// Of course, however, outbound channels are always allowed
	nodes[1].node.create_channel(last_random_pk, 100_000, 0, 42, None, None).unwrap();
	get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, last_random_pk);

	// If we fund the first channel, nodes[0] has a live on-chain channel with us, it is now
	// "protected" and can connect again.
	mine_transaction(&nodes[1], funding_tx.as_ref().unwrap());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	// Further, because the first channel was funded, we can open another channel with
	// last_random_pk.
	nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
	get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
}

#[test]
fn test_outbound_chans_unlimited() {
	// Test that we never refuse an outbound channel even if a peer is unfuned-channel-limited
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Note that create_network connects the nodes together for us

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	for _ in 0..channelmanager::MAX_UNFUNDED_CHANS_PER_PEER {
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}

	// Once we have MAX_UNFUNDED_CHANS_PER_PEER unfunded channels, new inbound channels will be
	// rejected.
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);

	// but we can still open an outbound channel.
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());

	// but even with such an outbound channel, additional inbound channels will still fail.
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);
}

#[test]
fn test_0conf_limiting() {
	// Tests that we properly limit inbound channels when we have the manual-channel-acceptance
	// flag set and (sometimes) accept channels as 0conf.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut settings = test_default_channel_config();
	settings.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(settings)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Note that create_network connects the nodes together for us

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	// First, get us up to MAX_UNFUNDED_CHANNEL_PEERS so we can test at the edge
	for _ in 0..channelmanager::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
		let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(&random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();

		nodes[1].node.handle_open_channel(&random_pk, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1].node.accept_inbound_channel(&temporary_channel_id, &random_pk, 23).unwrap();
			}
			_ => panic!("Unexpected event"),
		}
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, random_pk);
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}

	// If we try to accept a channel from another peer non-0conf it will fail.
	let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
		&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
	nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			match nodes[1].node.accept_inbound_channel(&temporary_channel_id, &last_random_pk, 23) {
				Err(APIError::APIMisuseError { err }) =>
					assert_eq!(err, "Too many peers with unfunded channels, refusing to accept new ones"),
				_ => panic!(),
			}
		}
		_ => panic!("Unexpected event"),
	}
	assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);

	// ...however if we accept the same channel 0conf it should work just fine.
	nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.accept_inbound_channel_from_trusted_peer_0conf(&temporary_channel_id, &last_random_pk, 23).unwrap();
		}
		_ => panic!("Unexpected event"),
	}
	get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
}

#[test]
fn test_trigger_lnd_force_close() {
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let user_config = test_default_channel_config();
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config), Some(user_config)]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);

	// Open a channel, immediately disconnect each other, and broadcast Alice's latest state.
	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	nodes[0].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id()).unwrap();
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);
	{
		let txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], funding_tx);
	}

	// Since they're disconnected, Bob won't receive Alice's `Error` message. Reconnect them
	// such that Bob sends a `ChannelReestablish` to Alice since the channel is still open from
	// their side.
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let channel_reestablish = get_event_msg!(
		nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()
	);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &channel_reestablish);

	// Alice should respond with an error since the channel isn't known, but a bogus
	// `ChannelReestablish` should be sent first, such that we actually trigger Bob to force
	// close even if it was an lnd node.
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	if let MessageSendEvent::SendChannelReestablish { node_id, msg } = &msg_events[0] {
		assert_eq!(*node_id, nodes[1].node.get_our_node_id());
		assert_eq!(msg.next_local_commitment_number, 0);
		assert_eq!(msg.next_remote_commitment_number, 0);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &msg);
	} else { panic!() };
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);
	let expected_close_reason = ClosureReason::ProcessingError {
		err: "Peer sent an invalid channel_reestablish to force close in a non-standard way".to_string()
	};
	check_closed_event!(nodes[1], 1, expected_close_reason, [nodes[0].node.get_our_node_id()], 100000);
	{
		let txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], funding_tx);
	}
}

#[test]
fn test_multi_hop_missing_secret() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	// Marshall an MPP route.
	let (mut route, payment_hash, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;
	route.paths[1].hops[0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1].hops[0].short_channel_id = chan_2_id;
	route.paths[1].hops[1].short_channel_id = chan_4_id;

	match nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0))
	.unwrap_err() {
		PaymentSendFailure::ParameterError(APIError::APIMisuseError { ref err }) => {
			assert!(regex::Regex::new(r"Payment secret is required for multi-path payments").unwrap().is_match(err))
		},
		_ => panic!("unexpected error")
	}
}

#[test]
fn test_channel_update_cached() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	nodes[0].node.force_close_channel_with_peer(&chan.2, &nodes[1].node.get_our_node_id(), None, true).unwrap();
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);

	// Confirm that the channel_update was not sent immediately to node[1] but was cached.
	let node_1_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(node_1_events.len(), 0);

	{
		// Assert that ChannelUpdate message has been added to node[0] pending broadcast messages
		let pending_broadcast_messages= nodes[0].node.pending_broadcast_messages.lock().unwrap();
		assert_eq!(pending_broadcast_messages.len(), 1);
	}

	// Test that we do not retrieve the pending broadcast messages when we are not connected to any peer
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[0].node.peer_disconnected(&nodes[2].node.get_our_node_id());
	nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	let node_0_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(node_0_events.len(), 0);

	// Now we reconnect to a peer
	nodes[0].node.peer_connected(&nodes[2].node.get_our_node_id(), &msgs::Init {
		features: nodes[2].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	nodes[2].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Confirm that get_and_clear_pending_msg_events correctly captures pending broadcast messages
	let node_0_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(node_0_events.len(), 1);
	match &node_0_events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => (),
		_ => panic!("Unexpected event"),
	}
	{
		// Assert that ChannelUpdate message has been cleared from nodes[0] pending broadcast messages
		let pending_broadcast_messages= nodes[0].node.pending_broadcast_messages.lock().unwrap();
		assert_eq!(pending_broadcast_messages.len(), 0);
	}
}