// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the channel open process.

use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::channelmonitor::{self, ChannelMonitorUpdateStep};
use crate::chain::transaction::OutPoint;
use crate::chain::{self, ChannelMonitorUpdateStatus};
use crate::events::{ClosureReason, Event, FundingInfo};
use crate::ln::channel::{
	get_holder_selected_channel_reserve_satoshis, ChannelError, InboundV1Channel,
	OutboundV1Channel, COINBASE_MATURITY, UNFUNDED_CHANNEL_AGE_LIMIT_TICKS,
};
use crate::ln::channelmanager::{
	self, BREAKDOWN_TIMEOUT, MAX_UNFUNDED_CHANNEL_PEERS, MAX_UNFUNDED_CHANS_PER_PEER,
};
use crate::ln::msgs::{
	AcceptChannel, BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent,
};
use crate::ln::types::ChannelId;
use crate::ln::{functional_test_utils::*, msgs};
use crate::sign::EntropySource;
use crate::util::config::{
	ChannelConfigOverrides, ChannelConfigUpdate, ChannelHandshakeConfigUpdate, UserConfig,
};
use crate::util::errors::APIError;
use crate::util::test_utils::{self, TestLogger};

use bitcoin::constants::ChainHash;
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::OutPoint as BitcoinOutPoint;
use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};

use lightning_macros::xtest;

use lightning_types::features::ChannelTypeFeatures;

#[test]
fn test_outbound_chans_unlimited() {
	// Test that we never refuse an outbound channel even if a peer is unfuned-channel-limited
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);

	// Note that create_network connects the nodes together for us
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a = nodes[0].node.get_our_node_id();
	let node_b = nodes[1].node.get_our_node_id();
	nodes[0].node.create_channel(node_b, 100_000, 0, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);

	for _ in 0..MAX_UNFUNDED_CHANS_PER_PEER {
		nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a);
		open_channel_msg.common_fields.temporary_channel_id =
			ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}

	// Once we have MAX_UNFUNDED_CHANS_PER_PEER unfunded channels, new inbound channels will be
	// rejected.
	nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
	assert_eq!(
		get_err_msg(&nodes[1], &node_a).channel_id,
		open_channel_msg.common_fields.temporary_channel_id
	);

	// but we can still open an outbound channel.
	nodes[1].node.create_channel(node_a, 100_000, 0, 42, None, None).unwrap();
	get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, node_a);

	// but even with such an outbound channel, additional inbound channels will still fail.
	nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
	assert_eq!(
		get_err_msg(&nodes[1], &node_a).channel_id,
		open_channel_msg.common_fields.temporary_channel_id
	);
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
	let node_b = nodes[1].node.get_our_node_id();
	nodes[0].node.create_channel(node_b, 100_000, 0, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);
	let init_msg = &msgs::Init {
		features: nodes[0].node.init_features(),
		networks: None,
		remote_network_address: None,
	};

	// First, get us up to MAX_UNFUNDED_CHANNEL_PEERS so we can test at the edge
	for _ in 0..MAX_UNFUNDED_CHANNEL_PEERS - 1 {
		let random_pk = PublicKey::from_secret_key(
			&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap(),
		);
		nodes[1].node.peer_connected(random_pk, init_msg, true).unwrap();

		nodes[1].node.handle_open_channel(random_pk, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1]
					.node
					.accept_inbound_channel(&temporary_channel_id, &random_pk, 23, None)
					.unwrap();
			},
			_ => panic!("Unexpected event"),
		}
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, random_pk);
		open_channel_msg.common_fields.temporary_channel_id =
			ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
	}

	// If we try to accept a channel from another peer non-0conf it will fail.
	let last_random_pk = PublicKey::from_secret_key(
		&nodes[0].node.secp_ctx,
		&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap(),
	);
	nodes[1].node.peer_connected(last_random_pk, init_msg, true).unwrap();
	nodes[1].node.handle_open_channel(last_random_pk, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			match nodes[1].node.accept_inbound_channel(
				&temporary_channel_id,
				&last_random_pk,
				23,
				None,
			) {
				Err(APIError::APIMisuseError { err }) => assert_eq!(
					err,
					"Too many peers with unfunded channels, refusing to accept new ones"
				),
				_ => panic!(),
			}
		},
		_ => panic!("Unexpected event"),
	}
	assert_eq!(
		get_err_msg(&nodes[1], &last_random_pk).channel_id,
		open_channel_msg.common_fields.temporary_channel_id
	);

	// ...however if we accept the same channel 0conf it should work just fine.
	nodes[1].node.handle_open_channel(last_random_pk, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.accept_inbound_channel_from_trusted_peer_0conf(
					&temporary_channel_id,
					&last_random_pk,
					23,
					None,
				)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	}
	get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
}

#[test]
fn test_inbound_anchors_manual_acceptance() {
	let mut anchors_cfg = test_default_channel_config();
	anchors_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	do_test_manual_inbound_accept_with_override(anchors_cfg, None);
}

#[test]
fn test_inbound_anchors_manual_acceptance_overridden() {
	let overrides = ChannelConfigOverrides {
		handshake_overrides: Some(ChannelHandshakeConfigUpdate {
			max_inbound_htlc_value_in_flight_percent_of_channel: Some(5),
			htlc_minimum_msat: Some(1000),
			minimum_depth: Some(2),
			to_self_delay: Some(200),
			max_accepted_htlcs: Some(5),
			channel_reserve_proportional_millionths: Some(20000),
		}),
		update_overrides: None,
	};

	let mut anchors_cfg = test_default_channel_config();
	anchors_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let accept_message = do_test_manual_inbound_accept_with_override(anchors_cfg, Some(overrides));
	assert_eq!(accept_message.common_fields.max_htlc_value_in_flight_msat, 5_000_000);
	assert_eq!(accept_message.common_fields.htlc_minimum_msat, 1_000);
	assert_eq!(accept_message.common_fields.minimum_depth, 2);
	assert_eq!(accept_message.common_fields.to_self_delay, 200);
	assert_eq!(accept_message.common_fields.max_accepted_htlcs, 5);
	assert_eq!(accept_message.channel_reserve_satoshis, 2_000);
}

#[test]
fn test_inbound_zero_fee_commitments_manual_acceptance() {
	let mut zero_fee_cfg = test_default_channel_config();
	zero_fee_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	do_test_manual_inbound_accept_with_override(zero_fee_cfg, None);
}

fn do_test_manual_inbound_accept_with_override(
	start_cfg: UserConfig, config_overrides: Option<ChannelConfigOverrides>,
) -> AcceptChannel {
	let mut mannual_accept_cfg = start_cfg.clone();
	mannual_accept_cfg.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(start_cfg.clone()), Some(start_cfg.clone()), Some(mannual_accept_cfg.clone())],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a = nodes[0].node.get_our_node_id();
	let node_b = nodes[1].node.get_our_node_id();
	nodes[0].node.create_channel(node_b, 100_000, 0, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);

	nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	match &msg_events[0] {
		MessageSendEvent::HandleError { node_id, action } => {
			assert_eq!(*node_id, node_a);
			match action {
				ErrorAction::SendErrorMessage { msg } => {
					assert_eq!(msg.data, "No channels with anchor outputs accepted".to_owned())
				},
				_ => panic!("Unexpected error action"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	nodes[2].node.handle_open_channel(node_a, &open_channel_msg);
	let events = nodes[2].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => nodes[2]
			.node
			.accept_inbound_channel(&temporary_channel_id, &node_a, 23, config_overrides)
			.unwrap(),
		_ => panic!("Unexpected event"),
	}
	get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, node_a)
}

#[test]
fn test_anchors_zero_fee_htlc_tx_downgrade() {
	// Tests that if both nodes support anchors, but the remote node does not want to accept
	// anchor channels at the moment, an error it sent to the local node such that it can retry
	// the channel without the anchors feature.
	let mut initiator_cfg = test_default_channel_config();
	initiator_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut receiver_cfg = test_default_channel_config();
	receiver_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	receiver_cfg.manually_accept_inbound_channels = true;

	let start_type = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	let end_type = ChannelTypeFeatures::only_static_remote_key();
	do_test_channel_type_downgrade(initiator_cfg, receiver_cfg, start_type, vec![end_type]);
}

#[test]
fn test_scid_privacy_downgrade() {
	// Tests downgrade from `anchors_zero_fee_commitments` with `option_scid_alias` when the
	// remote node advertises the features but does not accept the channel, asserting that
	// `option_scid_alias` is the last feature to be downgraded.
	let mut initiator_cfg = test_default_channel_config();
	initiator_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	initiator_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	initiator_cfg.channel_handshake_config.negotiate_scid_privacy = true;
	initiator_cfg.channel_handshake_config.announce_for_forwarding = false;

	let mut receiver_cfg = test_default_channel_config();
	receiver_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	receiver_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	receiver_cfg.channel_handshake_config.negotiate_scid_privacy = true;
	receiver_cfg.manually_accept_inbound_channels = true;

	let mut start_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
	start_type.set_scid_privacy_required();
	let mut with_anchors = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	with_anchors.set_scid_privacy_required();
	let mut with_scid_privacy = ChannelTypeFeatures::only_static_remote_key();
	with_scid_privacy.set_scid_privacy_required();
	let static_remote = ChannelTypeFeatures::only_static_remote_key();
	let downgrade_types = vec![with_anchors, with_scid_privacy, static_remote];

	do_test_channel_type_downgrade(initiator_cfg, receiver_cfg, start_type, downgrade_types);
}

#[test]
fn test_zero_fee_commitments_downgrade() {
	// Tests that the local node will retry without zero fee commitments in the case where the
	// remote node supports the feature but does not accept it.
	let mut initiator_cfg = test_default_channel_config();
	initiator_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	initiator_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut receiver_cfg = test_default_channel_config();
	receiver_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	receiver_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	receiver_cfg.manually_accept_inbound_channels = true;

	let start_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
	let downgrade_types = vec![
		ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
		ChannelTypeFeatures::only_static_remote_key(),
	];
	do_test_channel_type_downgrade(initiator_cfg, receiver_cfg, start_type, downgrade_types);
}

#[test]
fn test_zero_fee_commitments_downgrade_to_static_remote() {
	// Tests that the local node will retry with static remote key when zero fee commitments
	// are supported (but not accepted), but not legacy anchors.
	let mut initiator_cfg = test_default_channel_config();
	initiator_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	initiator_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut receiver_cfg = test_default_channel_config();
	receiver_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	receiver_cfg.manually_accept_inbound_channels = true;

	let start_type = ChannelTypeFeatures::anchors_zero_fee_commitments();
	let end_type = ChannelTypeFeatures::only_static_remote_key();
	do_test_channel_type_downgrade(initiator_cfg, receiver_cfg, start_type, vec![end_type]);
}

fn do_test_channel_type_downgrade(
	initiator_cfg: UserConfig, acceptor_cfg: UserConfig, start_type: ChannelTypeFeatures,
	downgrade_types: Vec<ChannelTypeFeatures>,
) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(initiator_cfg), Some(acceptor_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let error_message = "Channel force-closed";

	let node_a = nodes[0].node.get_our_node_id();
	let node_b = nodes[1].node.get_our_node_id();
	nodes[0].node.create_channel(node_b, 100_000, 0, 0, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);
	assert_eq!(open_channel_msg.common_fields.channel_type.as_ref().unwrap(), &start_type);

	for downgrade_type in downgrade_types {
		nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1]
					.node
					.force_close_broadcasting_latest_txn(
						&temporary_channel_id,
						&node_a,
						error_message.to_string(),
					)
					.unwrap();
			},
			_ => panic!("Unexpected event"),
		}

		let error_msg = get_err_msg(&nodes[1], &node_a);
		nodes[0].node.handle_error(node_b, &error_msg);

		open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);
		let channel_type = open_channel_msg.common_fields.channel_type.as_ref().unwrap();
		assert_eq!(channel_type, &downgrade_type);

		// Since nodes[1] should not have accepted the channel, it should
		// not have generated any events.
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}
}

#[test]
fn test_no_channel_downgrade() {
	// Tests that the local node will not retry when a `option_static_remote` channel is
	// rejected by a peer that advertises support for the feature.
	let initiator_cfg = test_default_channel_config();
	let mut receiver_cfg = test_default_channel_config();
	receiver_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	receiver_cfg.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(initiator_cfg), Some(receiver_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let error_message = "Channel force-closed";

	let node_a = nodes[0].node.get_our_node_id();
	let node_b = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b, 100_000, 0, 0, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b);
	let start_type = ChannelTypeFeatures::only_static_remote_key();
	assert_eq!(open_channel_msg.common_fields.channel_type.as_ref().unwrap(), &start_type);

	nodes[1].node.handle_open_channel(node_a, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.force_close_broadcasting_latest_txn(
					&temporary_channel_id,
					&node_a,
					error_message.to_string(),
				)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	}

	let error_msg = get_err_msg(&nodes[1], &node_a);
	nodes[0].node.handle_error(node_b, &error_msg);

	// Since nodes[0] could not retry the channel with a different type, it should close it.
	let chan_closed_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(chan_closed_events.len(), 1);
	if let Event::ChannelClosed { .. } = chan_closed_events[0] {
	} else {
		panic!();
	}
}

#[xtest(feature = "_externalize_tests")]
fn test_channel_resumption_fail_post_funding() {
	// If we fail to exchange funding with a peer prior to it disconnecting we'll resume the
	// channel open on reconnect, however if we do exchange funding we do not currently support
	// replaying it and here test that the channel closes.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 1_000_000, 0, 42, None, None).unwrap();
	let open_chan = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_chan);
	let accept_chan = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_chan);

	let (temp_chan_id, tx, funding_output) =
		create_funding_transaction(&nodes[0], &node_b_id, 1_000_000, 42);
	let new_chan_id = ChannelId::v1_from_funding_outpoint(funding_output);
	nodes[0].node.funding_transaction_generated(temp_chan_id, node_b_id, tx).unwrap();

	nodes[0].node.peer_disconnected(node_b_id);
	check_closed_events(
		&nodes[0],
		&[ExpectedCloseEvent::from_id_reason(new_chan_id, true, ClosureReason::DisconnectedPeer)],
	);

	// After ddf75afd16 we'd panic on reconnection if we exchanged funding info, so test that
	// explicitly here.
	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events(), Vec::new());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_insane_channel_opens() {
	// Stand up a network of 2 nodes
	use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_limits.max_funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(cfg.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Instantiate channel parameters where we push the maximum msats given our
	// funding satoshis
	let channel_value_sat = 31337; // same as funding satoshis
	let channel_reserve_satoshis =
		get_holder_selected_channel_reserve_satoshis(channel_value_sat, &cfg);
	let push_msat = (channel_value_sat - channel_reserve_satoshis) * 1000;

	// Have node0 initiate a channel to node1 with aforementioned parameters
	nodes[0].node.create_channel(node_b_id, channel_value_sat, push_msat, 42, None, None).unwrap();

	// Extract the channel open message from node0 to node1
	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	// Test helper that asserts we get the correct error string given a mutator
	// that supposedly makes the channel open message insane
	let insane_open_helper =
		|expected_error_str: &str, message_mutator: fn(msgs::OpenChannel) -> msgs::OpenChannel| {
			let open_channel_mutated = message_mutator(open_channel_message.clone());
			nodes[1].node.handle_open_channel(node_a_id, &open_channel_mutated);
			let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(msg_events.len(), 1);
			let expected_regex = regex::Regex::new(expected_error_str).unwrap();
			if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
				match action {
					&ErrorAction::SendErrorMessage { .. } => {
						nodes[1].logger.assert_log_regex(
							"lightning::ln::channelmanager",
							expected_regex,
							1,
						);
					},
					_ => panic!("unexpected event!"),
				}
			} else {
				assert!(false);
			}
		};

	use crate::ln::channelmanager::MAX_LOCAL_BREAKDOWN_TIMEOUT;

	// Test all mutations that would make the channel open message insane
	insane_open_helper(
		format!(
			"Per our config, funding must be at most {}. It was {}",
			TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1,
			TOTAL_BITCOIN_SUPPLY_SATOSHIS + 2
		)
		.as_str(),
		|mut msg| {
			msg.common_fields.funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS + 2;
			msg
		},
	);
	insane_open_helper(
		format!(
			"Funding must be smaller than the total bitcoin supply. It was {}",
			TOTAL_BITCOIN_SUPPLY_SATOSHIS
		)
		.as_str(),
		|mut msg| {
			msg.common_fields.funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS;
			msg
		},
	);

	insane_open_helper("Bogus channel_reserve_satoshis", |mut msg| {
		msg.channel_reserve_satoshis = msg.common_fields.funding_satoshis + 1;
		msg
	});

	insane_open_helper(
		r"push_msat \d+ was larger than channel amount minus reserve \(\d+\)",
		|mut msg| {
			msg.push_msat =
				(msg.common_fields.funding_satoshis - msg.channel_reserve_satoshis) * 1000 + 1;
			msg
		},
	);

	insane_open_helper("Peer never wants payout outputs?", |mut msg| {
		msg.common_fields.dust_limit_satoshis = msg.common_fields.funding_satoshis + 1;
		msg
	});

	insane_open_helper(
		r"Minimum htlc value \(\d+\) was larger than full channel value \(\d+\)",
		|mut msg| {
			msg.common_fields.htlc_minimum_msat =
				(msg.common_fields.funding_satoshis - msg.channel_reserve_satoshis) * 1000;
			msg
		},
	);

	insane_open_helper(
		"They wanted our payments to be delayed by a needlessly long period",
		|mut msg| {
			msg.common_fields.to_self_delay = MAX_LOCAL_BREAKDOWN_TIMEOUT + 1;
			msg
		},
	);

	insane_open_helper("0 max_accepted_htlcs makes for a useless channel", |mut msg| {
		msg.common_fields.max_accepted_htlcs = 0;
		msg
	});

	insane_open_helper("max_accepted_htlcs was 484. It must not be larger than 483", |mut msg| {
		msg.common_fields.max_accepted_htlcs = 484;
		msg
	});
}

#[test]
fn test_insane_zero_fee_channel_open() {
	let mut cfg = UserConfig::default();
	cfg.manually_accept_inbound_channels = true;
	cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(cfg.clone()), Some(cfg.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();

	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	let insane_open_helper =
		|expected_error_str: &str, message_mutator: fn(msgs::OpenChannel) -> msgs::OpenChannel| {
			let open_channel_mutated = message_mutator(open_channel_message.clone());
			nodes[1].node.handle_open_channel(node_a_id, &open_channel_mutated);

			let events = nodes[1].node.get_and_clear_pending_events();
			match events[0] {
				Event::OpenChannelRequest { temporary_channel_id, .. } => {
					match nodes[1].node.accept_inbound_channel(
						&temporary_channel_id,
						&nodes[0].node.get_our_node_id(),
						23,
						None,
					) {
						Ok(_) => panic!("Unexpected successful channel accept"),
						Err(e) => assert!(format!("{:?}", e).contains(expected_error_str)),
					}
				},
				_ => panic!("Unexpected event"),
			}

			let events = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			assert!(matches!(events[0], MessageSendEvent::HandleError { .. }));
		};

	insane_open_helper(
		"max_accepted_htlcs was 115. It must not be larger than 114".into(),
		|mut msg| {
			msg.common_fields.max_accepted_htlcs = 115;
			msg
		},
	);

	insane_open_helper("Zero Fee Channels must never attempt to use a fee".into(), |mut msg| {
		msg.common_fields.commitment_feerate_sat_per_1000_weight = 123;
		msg
	});
}

#[xtest(feature = "_externalize_tests")]
pub fn test_funding_exceeds_no_wumbo_limit() {
	// Test that if a peer does not support wumbo channels, we'll refuse to open a wumbo channel to
	// them.
	use crate::ln::channel::MAX_FUNDING_SATOSHIS_NO_WUMBO;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut features = channelmanager::provided_init_features(&test_default_channel_config());
	features.clear_wumbo();
	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	match nodes[0].node.create_channel(
		node_b_id,
		MAX_FUNDING_SATOSHIS_NO_WUMBO + 1,
		0,
		42,
		None,
		None,
	) {
		Err(APIError::APIMisuseError { err }) => {
			let exp_err = format!(
				"funding_value must not exceed {}, it was {}",
				MAX_FUNDING_SATOSHIS_NO_WUMBO,
				MAX_FUNDING_SATOSHIS_NO_WUMBO + 1
			);
			assert_eq!(err, exp_err);
		},
		_ => panic!(),
	}
}

fn do_test_sanity_on_in_flight_opens(steps: u8) {
	// Previously, we had issues deserializing channels when we hadn't connected the first block
	// after creation. To catch that and similar issues, we lean on the Node::drop impl to test
	// serialization round-trips and simply do steps towards opening a channel and then drop the
	// Node objects.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	if steps & 0b1000_0000 != 0 {
		let block = create_dummy_block(nodes[0].best_block_hash(), 42, Vec::new());
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
	}

	if steps & 0x0f == 0 {
		return;
	}
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	if steps & 0x0f == 1 {
		return;
	}
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);

	if steps & 0x0f == 2 {
		return;
	}
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let (temporary_channel_id, tx, _) =
		create_funding_transaction(&nodes[0], &node_b_id, 100000, 42);

	if steps & 0x0f == 3 {
		return;
	}
	nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, tx.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 0);
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);

	let channel_id = ChannelId::v1_from_funding_txid(
		funding_created.funding_txid.as_byte_array(),
		funding_created.funding_output_index,
	);

	if steps & 0x0f == 4 {
		return;
	}
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);

	if steps & 0x0f == 5 {
		return;
	}
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}

	expect_channel_pending_event(&nodes[0], &node_b_id);
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 0);

	if steps & 0x0f == 6 {
		return;
	}
	create_chan_between_nodes_with_value_confirm_first(&nodes[0], &nodes[1], &tx, 2);

	if steps & 0x0f == 7 {
		return;
	}
	confirm_transaction_at(&nodes[0], &tx, 2);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);
	create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
	expect_channel_ready_event(&nodes[0], &node_b_id);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_sanity_on_in_flight_opens() {
	do_test_sanity_on_in_flight_opens(0);
	do_test_sanity_on_in_flight_opens(0 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(1);
	do_test_sanity_on_in_flight_opens(1 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(2);
	do_test_sanity_on_in_flight_opens(2 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(3);
	do_test_sanity_on_in_flight_opens(3 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(4);
	do_test_sanity_on_in_flight_opens(4 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(5);
	do_test_sanity_on_in_flight_opens(5 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(6);
	do_test_sanity_on_in_flight_opens(6 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(7);
	do_test_sanity_on_in_flight_opens(7 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(8);
	do_test_sanity_on_in_flight_opens(8 | 0b1000_0000);
}

#[xtest(feature = "_externalize_tests")]
#[should_panic]
pub fn bolt2_open_channel_sending_node_checks_part1() {
	//This test needs to be on its own as we are catching a panic
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Force duplicate randomness for every get-random call
	for node in nodes.iter() {
		*node.keys_manager.override_random_bytes.lock().unwrap() = Some([0; 32]);
	}

	// BOLT #2 spec: Sending node must ensure temporary_channel_id is unique from any other channel ID with the same peer.
	let channel_value_satoshis = 10000;
	let push_msat = 10001;
	nodes[0]
		.node
		.create_channel(node_b_id, channel_value_satoshis, push_msat, 42, None, None)
		.unwrap();
	let node0_to_1_send_open_channel =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &node0_to_1_send_open_channel);
	get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);

	// Create a second channel with the same random values. This used to panic due to a colliding
	// channel_id, but now panics due to a colliding outbound SCID alias.
	assert!(nodes[0]
		.node
		.create_channel(node_b_id, channel_value_satoshis, push_msat, 42, None, None)
		.is_err());
}

#[xtest(feature = "_externalize_tests")]
pub fn bolt2_open_channel_sending_node_checks_part2() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// BOLT #2 spec: Sending node must set push_msat to equal or less than 1000 * funding_satoshis
	let channel_value_satoshis = 10000;
	// Test when push_msat is equal to 1000 * funding_satoshis.
	let push_msat = 1000 * channel_value_satoshis + 1;
	assert!(nodes[0]
		.node
		.create_channel(node_b_id, channel_value_satoshis, push_msat, 42, None, None)
		.is_err());

	nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();

	let node0_to_1_send_open_channel =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	// BOLT #2 spec: Sending node should set to_self_delay sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehaviour by the receiver.
	assert!(BREAKDOWN_TIMEOUT > 0);
	assert!(node0_to_1_send_open_channel.common_fields.to_self_delay == BREAKDOWN_TIMEOUT);

	// BOLT #2 spec: Sending node must ensure the chain_hash value identifies the chain it wishes to open the channel within.
	let chain_hash = ChainHash::using_genesis_block(Network::Testnet);
	assert_eq!(node0_to_1_send_open_channel.common_fields.chain_hash, chain_hash);
}

#[xtest(feature = "_externalize_tests")]
pub fn bolt2_open_channel_sane_dust_limit() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let value_sats = 1000000;
	let push_msat = 10001;
	nodes[0].node.create_channel(node_b_id, value_sats, push_msat, 42, None, None).unwrap();
	let mut node0_to_1_send_open_channel =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	node0_to_1_send_open_channel.common_fields.dust_limit_satoshis = 547;
	node0_to_1_send_open_channel.channel_reserve_satoshis = 100001;

	nodes[1].node.handle_open_channel(node_a_id, &node0_to_1_send_open_channel);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	let err_msg = match events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg }, ..
		} => msg.clone(),
		_ => panic!("Unexpected event"),
	};
	assert_eq!(
		err_msg.data,
		"dust_limit_satoshis (547) is greater than the implementation limit (546)"
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_user_configurable_csv_delay() {
	// We test our channel constructors yield errors when we pass them absurd csv delay

	let mut low_our_to_self_config = UserConfig::default();
	low_our_to_self_config.channel_handshake_config.our_to_self_delay = 6;
	let mut high_their_to_self_config = UserConfig::default();
	high_their_to_self_config.channel_handshake_limits.their_to_self_delay = 100;
	let user_cfgs = [Some(high_their_to_self_config.clone()), None];
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let logger = TestLogger::new();

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in OutboundV1Channel::new()
	if let Err(error) = OutboundV1Channel::new(
		&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager,
		&nodes[0].keys_manager,
		node_b_id,
		&nodes[1].node.init_features(),
		1000000,
		1000000,
		0,
		&low_our_to_self_config,
		0,
		42,
		None,
		&logger,
	) {
		match error {
			APIError::APIMisuseError { err } => {
				assert!(regex::Regex::new(
					r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks"
				)
				.unwrap()
				.is_match(err.as_str()));
			},
			_ => panic!("Unexpected event"),
		}
	} else {
		assert!(false)
	}

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in InboundV1Channel::new()
	nodes[1].node.create_channel(node_a_id, 1000000, 1000000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, node_a_id);
	open_channel.common_fields.to_self_delay = 200;
	if let Err(error) = InboundV1Channel::new(
		&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager,
		&nodes[0].keys_manager,
		node_b_id,
		&nodes[0].node.channel_type_features(),
		&nodes[1].node.init_features(),
		&open_channel,
		0,
		&low_our_to_self_config,
		0,
		&nodes[0].logger,
		/*is_0conf=*/ false,
	) {
		match error {
			ChannelError::Close((err, _)) => {
				let regex = regex::Regex::new(
					r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks",
				)
				.unwrap();
				assert!(regex.is_match(err.as_str()));
			},
			_ => panic!("Unexpected event"),
		}
	} else {
		assert!(false);
	}

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Chanel::accept_channel()
	nodes[0].node.create_channel(node_b_id, 1000000, 1000000, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);

	let mut accept_channel =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	accept_channel.common_fields.to_self_delay = 200;
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);
	let reason_msg;
	if let MessageSendEvent::HandleError { ref action, .. } =
		nodes[0].node.get_and_clear_pending_msg_events()[0]
	{
		match action {
			&ErrorAction::SendErrorMessage { ref msg } => {
				assert!(regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap().is_match(msg.data.as_str()));
				reason_msg = msg.data.clone();
			},
			_ => {
				panic!();
			},
		}
	} else {
		panic!();
	}
	let reason = ClosureReason::ProcessingError { err: reason_msg };
	check_closed_event!(nodes[0], 1, reason, [node_b_id], 1000000);

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in InboundV1Channel::new()
	nodes[1].node.create_channel(node_a_id, 1000000, 1000000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, node_a_id);
	open_channel.common_fields.to_self_delay = 200;
	if let Err(error) = InboundV1Channel::new(
		&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager,
		&nodes[0].keys_manager,
		node_b_id,
		&nodes[0].node.channel_type_features(),
		&nodes[1].node.init_features(),
		&open_channel,
		0,
		&high_their_to_self_config,
		0,
		&nodes[0].logger,
		/*is_0conf=*/ false,
	) {
		match error {
			ChannelError::Close((err, _)) => {
				let regex = regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap();
				assert!(regex.is_match(err.as_str()));
			},
			_ => panic!("Unexpected event"),
		}
	} else {
		assert!(false);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_manually_accept_inbound_channel_request() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	manually_accept_conf.channel_handshake_config.minimum_depth = 1;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(manually_accept_conf))
		.unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// accepting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let config_overrides = ChannelConfigOverrides {
		handshake_overrides: Some(ChannelHandshakeConfigUpdate {
			max_inbound_htlc_value_in_flight_percent_of_channel: None,
			htlc_minimum_msat: None,
			minimum_depth: None,
			to_self_delay: None,
			max_accepted_htlcs: Some(3),
			channel_reserve_proportional_millionths: None,
		}),
		update_overrides: Some(ChannelConfigUpdate {
			forwarding_fee_proportional_millionths: None,
			forwarding_fee_base_msat: Some(555),
			cltv_expiry_delta: None,
			max_dust_htlc_exposure_msat: None,
			force_close_avoidance_max_fee_satoshis: None,
			accept_underpaying_htlcs: None,
		}),
	};
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			let config = Some(config_overrides);
			nodes[1]
				.node
				.accept_inbound_channel(&temporary_channel_id, &node_a_id, 23, config)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	}

	let accept_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(accept_msg_ev.len(), 1);

	let ref accept_channel: AcceptChannel;
	match accept_msg_ev[0] {
		MessageSendEvent::SendAcceptChannel { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_a_id);

			// Assert overriden handshake parameter.
			assert_eq!(msg.common_fields.max_accepted_htlcs, 3);

			accept_channel = msg;
		},
		_ => panic!("Unexpected event"),
	}

	// Continue channel opening process until channel update messages are sent.
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);
	let (temp_channel_id, tx, funding_outpoint) =
		create_funding_transaction(&nodes[0], &node_b_id, 100_000, 42);
	nodes[0]
		.node
		.unsafe_manual_funding_transaction_generated(temp_channel_id, node_b_id, funding_outpoint)
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed);
	check_added_monitors(&nodes[0], 1);
	let events = &nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		crate::events::Event::FundingTxBroadcastSafe { funding_txo, .. } => {
			assert_eq!(funding_txo.txid, funding_outpoint.txid);
			assert_eq!(funding_txo.vout, funding_outpoint.index.into());
		},
		_ => panic!("Unexpected event"),
	};
	match &events[1] {
		crate::events::Event::ChannelPending { counterparty_node_id, .. } => {
			assert_eq!(node_b_id, *counterparty_node_id);
		},
		_ => panic!("Unexpected event"),
	};

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	let as_channel_ready = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_a_id);
	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
	nodes[0].node.handle_channel_ready(node_b_id, &as_channel_ready);

	expect_channel_ready_event(&nodes[0], &node_b_id);
	expect_channel_ready_event(&nodes[1], &node_a_id);

	// Assert that the overriden base fee surfaces in the channel update.
	let channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);
	assert_eq!(channel_update.contents.fee_base_msat, 555);

	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_manually_reject_inbound_channel_request() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(manually_accept_conf))
		.unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// rejecting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	let err = "Channel force-closed".to_string();
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.force_close_broadcasting_latest_txn(&temporary_channel_id, &node_a_id, err)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	}

	let close_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(close_msg_ev.len(), 1);

	match close_msg_ev[0] {
		MessageSendEvent::HandleError { ref node_id, .. } => {
			assert_eq!(*node_id, node_a_id);
		},
		_ => panic!("Unexpected event"),
	}

	// There should be no more events to process, as the channel was never opened.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_can_not_accept_inbound_channel_twice() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(manually_accept_conf))
		.unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// accepting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.accept_inbound_channel(&temporary_channel_id, &node_a_id, 0, None)
				.unwrap();
			let api_res =
				nodes[1].node.accept_inbound_channel(&temporary_channel_id, &node_a_id, 0, None);
			match api_res {
				Err(APIError::APIMisuseError { err }) => {
					assert_eq!(err, "No such channel awaiting to be accepted.");
				},
				Ok(_) => panic!("Channel shouldn't be possible to be accepted twice"),
				Err(e) => panic!("Unexpected Error {:?}", e),
			}
		},
		_ => panic!("Unexpected event"),
	}

	// Ensure that the channel wasn't closed after attempting to accept it twice.
	let accept_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(accept_msg_ev.len(), 1);

	match accept_msg_ev[0] {
		MessageSendEvent::SendAcceptChannel { ref node_id, .. } => {
			assert_eq!(*node_id, node_a_id);
		},
		_ => panic!("Unexpected event"),
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_can_not_accept_unknown_inbound_channel() {
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);

	let node_b_id = nodes[1].node.get_our_node_id();

	let unknown_channel_id = ChannelId::new_zero();
	let api_res = nodes[0].node.accept_inbound_channel(&unknown_channel_id, &node_b_id, 0, None);
	match api_res {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(err, "No such channel awaiting to be accepted.");
		},
		Ok(_) => panic!("It shouldn't be possible to accept an unkown channel"),
		Err(e) => panic!("Unexpected Error: {:?}", e),
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_temporary_channel_id_from_different_peers() {
	// Tests that we can accept two different `OpenChannel` requests with the same
	// `temporary_channel_id`, as long as they are from different peers.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create an first channel channel
	nodes[1].node.create_channel(node_a_id, 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg_chan_1_0 =
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, node_a_id);

	// Create an second channel
	nodes[2].node.create_channel(node_a_id, 100000, 10001, 43, None, None).unwrap();
	let mut open_chan_msg_chan_2_0 =
		get_event_msg!(nodes[2], MessageSendEvent::SendOpenChannel, node_a_id);

	// Modify the `OpenChannel` from `nodes[2]` to `nodes[0]` to ensure that it uses the same
	// `temporary_channel_id` as the `OpenChannel` from nodes[1] to nodes[0].
	open_chan_msg_chan_2_0.common_fields.temporary_channel_id =
		open_chan_msg_chan_1_0.common_fields.temporary_channel_id;

	// Assert that `nodes[0]` can accept both `OpenChannel` requests, even though they use the same
	// `temporary_channel_id` as they are from different peers.
	nodes[0].node.handle_open_channel(node_b_id, &open_chan_msg_chan_1_0);
	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::SendAcceptChannel { node_id, msg } => {
				assert_eq!(node_id, &node_b_id);
				assert_eq!(
					msg.common_fields.temporary_channel_id,
					open_chan_msg_chan_1_0.common_fields.temporary_channel_id
				);
			},
			_ => panic!("Unexpected event"),
		}
	}

	nodes[0].node.handle_open_channel(node_c_id, &open_chan_msg_chan_2_0);
	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::SendAcceptChannel { node_id, msg } => {
				assert_eq!(node_id, &node_c_id);
				assert_eq!(
					msg.common_fields.temporary_channel_id,
					open_chan_msg_chan_1_0.common_fields.temporary_channel_id
				);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_funding_err_in_funding() {
	// Test that if we have a live channel with one peer, then another peer comes along and tries
	// to create a second channel with the same txid we'll fail and not overwrite the
	// outpoint_to_peer map in `ChannelManager`.
	//
	// This was previously broken.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let (_, _, _, real_channel_id, funding_tx) = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let real_chan_funding_txo =
		chain::transaction::OutPoint { txid: funding_tx.compute_txid(), index: 0 };
	assert_eq!(ChannelId::v1_from_funding_outpoint(real_chan_funding_txo), real_channel_id);

	nodes[2].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[2], MessageSendEvent::SendOpenChannel, node_b_id);
	let node_c_temp_chan_id = open_chan_msg.common_fields.temporary_channel_id;
	open_chan_msg.common_fields.temporary_channel_id = real_channel_id;
	nodes[1].node.handle_open_channel(node_c_id, &open_chan_msg);
	let mut accept_chan_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_c_id);
	accept_chan_msg.common_fields.temporary_channel_id = node_c_temp_chan_id;
	nodes[2].node.handle_accept_channel(node_b_id, &accept_chan_msg);

	// Now that we have a second channel with the same funding txo, send a bogus funding message
	// and let nodes[1] remove the inbound channel.
	let (_, fund_tx, _) = create_funding_transaction(&nodes[2], &node_b_id, 100_000, 42);

	nodes[2].node.funding_transaction_generated(node_c_temp_chan_id, node_b_id, fund_tx).unwrap();

	let mut funding_created_msg =
		get_event_msg!(nodes[2], MessageSendEvent::SendFundingCreated, node_b_id);
	funding_created_msg.temporary_channel_id = real_channel_id;
	// Make the signature invalid by changing the funding output
	funding_created_msg.funding_output_index += 10;
	nodes[1].node.handle_funding_created(node_c_id, &funding_created_msg);
	get_err_msg(&nodes[1], &node_c_id);
	let err = "Invalid funding_created signature from peer".to_owned();
	let reason = ClosureReason::ProcessingError { err };
	let expected_closing = ExpectedCloseEvent::from_id_reason(real_channel_id, false, reason);
	check_closed_events(&nodes[1], &[expected_closing]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_chan_id() {
	// Test that if a given peer tries to open a channel with the same channel_id as one that is
	// already open we reject it and keep the old channel.
	//
	// Previously, full_stack_target managed to figure out that if you tried to open two channels
	// with the same funding output (ie post-funding channel_id), we'd create a monitor update for
	// the existing channel when we detect the duplicate new channel, screwing up our monitor
	// updating logic for the existing channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create an initial channel
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_chan_msg);
	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	// Try to create a second channel with the same temporary_channel_id as the first and check
	// that it is rejected.
	nodes[1].node.handle_open_channel(node_a_id, &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError {
				action: ErrorAction::SendErrorMessage { ref msg },
				node_id,
			} => {
				// Technically, at this point, nodes[1] would be justified in thinking both the
				// first (valid) and second (invalid) channels are closed, given they both have
				// the same non-temporary channel_id. However, currently we do not, so we just
				// move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.common_fields.temporary_channel_id);
				assert_eq!(node_id, node_a_id);
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Move the first channel through the funding flow...
	let (temp_channel_id, tx, _) = create_funding_transaction(&nodes[0], &node_b_id, 100000, 42);

	nodes[0].node.funding_transaction_generated(temp_channel_id, node_b_id, tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	let channel_id = ChannelId::v1_from_funding_txid(
		funding_created_msg.funding_txid.as_byte_array(),
		funding_created_msg.funding_output_index,
	);

	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msg);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);

	let funding_outpoint = crate::chain::transaction::OutPoint {
		txid: funding_created_msg.funding_txid,
		index: funding_created_msg.funding_output_index,
	};
	let channel_id = ChannelId::v1_from_funding_outpoint(funding_outpoint);

	// Now we have the first channel past funding_created (ie it has a txid-based channel_id, not a
	// temporary one).

	// First try to open a second channel with a temporary channel id equal to the txid-based one.
	// Technically this is allowed by the spec, but we don't support it and there's little reason
	// to. Still, it shouldn't cause any other issues.
	open_chan_msg.common_fields.temporary_channel_id = channel_id;
	nodes[1].node.handle_open_channel(node_a_id, &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError {
				action: ErrorAction::SendErrorMessage { ref msg },
				node_id,
			} => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.common_fields.temporary_channel_id);
				assert_eq!(node_id, node_a_id);
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Now try to create a second channel which has a duplicate funding output.
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_chan_2_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_chan_2_msg);
	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);
	create_funding_transaction(&nodes[0], &node_b_id, 100000, 42); // Get and check the FundingGenerationReady event

	let funding_created = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let mut a_peer_state = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		// Once we call `get_funding_created` the channel has a duplicate channel_id as
		// another channel in the ChannelManager - an invalid state. Thus, we'd panic later when we
		// try to create another channel. Instead, we drop the channel entirely here (leaving the
		// channelmanager in a possibly nonsense state instead).
		let chan_id = open_chan_2_msg.common_fields.temporary_channel_id;
		let mut channel = a_peer_state.channel_by_id.remove(&chan_id).unwrap();

		if let Some(mut chan) = channel.as_unfunded_outbound_v1_mut() {
			let logger = test_utils::TestLogger::new();
			chan.get_funding_created(tx.clone(), funding_outpoint, false, &&logger)
				.map_err(|_| ())
				.unwrap()
		} else {
			panic!("Unexpected Channel phase")
		}
		.unwrap()
	};
	check_added_monitors(&nodes[0], 0);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	// At this point we'll look up if the channel_id is present and immediately fail the channel
	// without trying to persist the `ChannelMonitor`.
	check_added_monitors(&nodes[1], 0);

	let reason = ClosureReason::ProcessingError {
		err: "Already had channel with the new channel_id".to_owned(),
	};
	let close_event =
		ExpectedCloseEvent::from_id_reason(funding_created.temporary_channel_id, false, reason);
	check_closed_events(&nodes[1], &[close_event]);

	// ...still, nodes[1] will reject the duplicate channel.
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError {
				action: ErrorAction::SendErrorMessage { ref msg },
				node_id,
			} => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, funding_created.temporary_channel_id);
				assert_eq!(node_id, node_a_id);
			},
			_ => panic!("Unexpected event"),
		}
	}

	// finally, finish creating the original channel and send a payment over it to make sure
	// everything is functional.
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, channel_id);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[0], &node_b_id);

	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 0);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);

	let (channel_ready, _) =
		create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) =
		create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &as_update, &bs_update);

	send_payment(&nodes[0], &[&nodes[1]], 8000000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_invalid_funding_tx() {
	// Test that we properly handle invalid funding transactions sent to us from a peer.
	//
	// Previously, all other major lightning implementations had failed to properly sanitize
	// funding transactions from their counterparties, leading to a multi-implementation critical
	// security vulnerability (though we always sanitized properly, we've previously had
	// un-released crashes in the sanitization process).
	//
	// Further, if the funding transaction is consensus-valid, confirms, and is later spent, we'd
	// previously have crashed in `ChannelMonitor` even though we closed the channel as bogus and
	// gave up on it. We test this here by generating such a transaction.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100_000, 10_000, 42, None, None).unwrap();
	nodes[1].node.handle_open_channel(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id),
	);
	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	let (temporary_channel_id, mut tx, _) =
		create_funding_transaction(&nodes[0], &node_b_id, 100_000, 42);

	// Create a witness program which can be spent by a 4-empty-stack-elements witness and which is
	// 136 bytes long. This matches our "accepted HTLC preimage spend" matching, previously causing
	// a panic as we'd try to extract a 32 byte preimage from a witness element without checking
	// its length.
	let mut wit_program: Vec<u8> =
		channelmonitor::deliberately_bogus_accepted_htlc_witness_program();
	let wit_program_script: ScriptBuf = wit_program.into();
	for output in tx.output.iter_mut() {
		// Make the confirmed funding transaction have a bogus script_pubkey
		output.script_pubkey = ScriptBuf::new_p2wsh(&wit_program_script.wscript_hash());
	}

	nodes[0]
		.node
		.funding_transaction_generated_unchecked(temporary_channel_id, node_b_id, tx.clone(), 0)
		.unwrap();
	nodes[1].node.handle_funding_created(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id),
	);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	nodes[0].node.handle_funding_signed(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id),
	);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &node_b_id);

	let events_1 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 0);

	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

	let expected_err = "funding tx had wrong script/value or output index";
	confirm_transaction_at(&nodes[1], &tx, 1);

	let reason = ClosureReason::ProcessingError { err: expected_err.to_string() };
	check_closed_event!(nodes[1], 1, reason, [node_a_id], 100000);

	check_added_monitors(&nodes[1], 1);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	if let MessageSendEvent::HandleError { node_id, action } = &events_2[0] {
		assert_eq!(*node_id, node_a_id);
		if let msgs::ErrorAction::SendErrorMessage { msg } = action {
			assert_eq!(
				msg.data,
				"Channel closed because of an exception: ".to_owned() + expected_err
			);
		} else {
			panic!();
		}
	} else {
		panic!();
	}
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// Now confirm a spend of the (bogus) funding transaction. As long as the witness is 5 elements
	// long the ChannelMonitor will try to read 32 bytes from the second-to-last element, panicing
	// as its not 32 bytes long.
	let mut spend_tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: tx
			.output
			.iter()
			.enumerate()
			.map(|(idx, _)| TxIn {
				previous_output: BitcoinOutPoint { txid: tx.compute_txid(), vout: idx as u32 },
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::from_slice(
					&channelmonitor::deliberately_bogus_accepted_htlc_witness(),
				),
			})
			.collect(),
		output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
	};
	check_spends!(spend_tx, tx);
	mine_transaction(&nodes[1], &spend_tx);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_coinbase_funding_tx() {
	// Miners are able to fund channels directly from coinbase transactions, however
	// by consensus rules, outputs of a coinbase transaction are encumbered by a 100
	// block maturity timelock. To ensure that a (non-0conf) channel like this is enforceable
	// on-chain, the minimum depth is updated to 100 blocks for coinbase funding transactions.
	//
	// Note that 0conf channels with coinbase funding transactions are unaffected and are
	// immediately operational after opening.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);

	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	// Create the coinbase funding transaction.
	let (channel_id, tx, _) =
		create_coinbase_funding_transaction(&nodes[0], &node_b_id, 100000, 42);

	nodes[0].node.funding_transaction_generated(channel_id, node_b_id, tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);

	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);

	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed);
	check_added_monitors(&nodes[0], 1);

	expect_channel_pending_event(&nodes[0], &node_b_id);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// Starting at height 0, we "confirm" the coinbase at height 1.
	confirm_transaction_at(&nodes[0], &tx, 1);
	// We connect 98 more blocks to have 99 confirmations for the coinbase transaction.
	connect_blocks(&nodes[0], COINBASE_MATURITY - 2);
	// Check that we have no pending message events (we have not queued a `channel_ready` yet).
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	// Now connect one more block which results in 100 confirmations of the coinbase transaction.
	connect_blocks(&nodes[0], 1);
	// There should now be a `channel_ready` which can be handled.
	let _ = &nodes[1].node.handle_channel_ready(
		node_a_id,
		&get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReady, node_b_id),
	);

	confirm_transaction_at(&nodes[1], &tx, 1);
	connect_blocks(&nodes[1], COINBASE_MATURITY - 2);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	connect_blocks(&nodes[1], 1);
	expect_channel_ready_event(&nodes[1], &node_a_id);
	create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_non_final_funding_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_channel_id =
		nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_message);
	let accept_channel_message =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel_message);

	let best_height = nodes[0].node.best_block.read().unwrap().height;

	let chan_id = *nodes[0].network_chan_count.borrow();
	let events = nodes[0].node.get_and_clear_pending_events();
	let input = TxIn {
		previous_output: BitcoinOutPoint::null(),
		script_sig: bitcoin::ScriptBuf::new(),
		sequence: Sequence(1),
		witness: Witness::from_slice(&[&[1]]),
	};
	assert_eq!(events.len(), 1);
	let mut tx = match events[0] {
		Event::FundingGenerationReady { ref channel_value_satoshis, ref output_script, .. } => {
			// Timelock the transaction _beyond_ the best client height + 1.
			Transaction {
				version: Version(chan_id as i32),
				lock_time: LockTime::from_height(best_height + 2).unwrap(),
				input: vec![input],
				output: vec![TxOut {
					value: Amount::from_sat(*channel_value_satoshis),
					script_pubkey: output_script.clone(),
				}],
			}
		},
		_ => panic!("Unexpected event"),
	};
	// Transaction should fail as it's evaluated as non-final for propagation.
	match nodes[0].node.funding_transaction_generated(temp_channel_id, node_b_id, tx.clone()) {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(format!("Funding transaction absolute timelock is non-final"), err);
		},
		_ => panic!(),
	}
	let err = "Error in transaction funding: Misuse error: Funding transaction absolute timelock is non-final";
	let reason = ClosureReason::ProcessingError { err: err.to_owned() };
	let event = ExpectedCloseEvent::from_id_reason(temp_channel_id, false, reason);
	check_closed_events(&nodes[0], &[event]);
	assert_eq!(get_err_msg(&nodes[0], &node_b_id).data, err);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_non_final_funding_tx_within_headroom() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_channel_id =
		nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_message);
	let accept_channel_message =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel_message);

	let best_height = nodes[0].node.best_block.read().unwrap().height;

	let chan_id = *nodes[0].network_chan_count.borrow();
	let events = nodes[0].node.get_and_clear_pending_events();
	let input = TxIn {
		previous_output: BitcoinOutPoint::null(),
		script_sig: bitcoin::ScriptBuf::new(),
		sequence: Sequence(1),
		witness: Witness::from_slice(&[[1]]),
	};
	assert_eq!(events.len(), 1);
	let mut tx = match events[0] {
		Event::FundingGenerationReady { ref channel_value_satoshis, ref output_script, .. } => {
			// Timelock the transaction within a +1 headroom from the best block.
			Transaction {
				version: Version(chan_id as i32),
				lock_time: LockTime::from_consensus(best_height + 1),
				input: vec![input],
				output: vec![TxOut {
					value: Amount::from_sat(*channel_value_satoshis),
					script_pubkey: output_script.clone(),
				}],
			}
		},
		_ => panic!("Unexpected event"),
	};

	// Transaction should be accepted if it's in a +1 headroom from best block.
	nodes[0].node.funding_transaction_generated(temp_channel_id, node_b_id, tx.clone()).unwrap();
	get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_close_when_not_timely_accepted() {
	// Create network of two nodes
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Simulate peer-disconnects mid-handshake
	// The channel is initiated from the node 0 side,
	// but the nodes disconnect before node 1 could send accept channel
	let create_chan_id =
		nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert_eq!(open_channel_msg.common_fields.temporary_channel_id, create_chan_id);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	// Make sure that we have not removed the OutboundV1Channel from node[0] immediately.
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Since channel was inbound from node[1] perspective, it should have been dropped immediately.
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// In the meantime, some time passes.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	// Since we disconnected from peer and did not connect back within time,
	// we should have forced-closed the channel by now.
	let reason = ClosureReason::FundingTimedOut;
	check_closed_event!(nodes[0], 1, reason, [node_b_id], 100000);
	assert_eq!(nodes[0].node.list_channels().len(), 0);

	{
		// Since accept channel message was never received
		// The channel should be forced close by now from node 0 side
		// and the peer removed from per_peer_state
		let node_0_per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		assert_eq!(node_0_per_peer_state.len(), 0);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_rebroadcast_open_channel_when_reconnect_mid_handshake() {
	// Create network of two nodes
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Simulate peer-disconnects mid-handshake
	// The channel is initiated from the node 0 side,
	// but the nodes disconnect before node 1 could send accept channel
	let create_chan_id =
		nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert_eq!(open_channel_msg.common_fields.temporary_channel_id, create_chan_id);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	// Make sure that we have not removed the OutboundV1Channel from node[0] immediately.
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Since channel was inbound from node[1] perspective, it should have been immediately dropped.
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// The peers now reconnect
	let init_msg = msgs::Init {
		features: nodes[0].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();

	// Make sure the SendOpenChannel message is added to node_0 pending message events
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::SendOpenChannel { msg, .. } => assert_eq!(msg, &open_channel_msg),
		_ => panic!("Unexpected message."),
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_batch_channel_open() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(
		&nodes[0],
		&[(&nodes[1], 100_000, 0, 42, None), (&nodes[2], 200_000, 0, 43, None)],
	);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);

	// Go through the funding_created and funding_signed flow with node 2.
	nodes[2].node.handle_funding_created(node_a_id, &funding_created_msgs[1]);
	check_added_monitors(&nodes[2], 1);
	expect_channel_pending_event(&nodes[2], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, node_a_id);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_funding_signed(node_c_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before persisting all monitors has been
	// completed.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);
	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);

	// Complete the persistence of the monitor.
	nodes[0].chain_monitor.complete_sole_pending_chan_update(&ChannelId::v1_from_funding_outpoint(
		OutPoint { txid: tx.compute_txid(), index: 1 },
	));
	let events = nodes[0].node.get_and_clear_pending_events();

	// The transaction should only have been broadcast now.
	let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 1);
	assert_eq!(broadcasted_txs[0], tx);

	assert_eq!(events.len(), 2);
	assert!(events.iter().any(|e| matches!(
		*e,
		crate::events::Event::ChannelPending {
			ref counterparty_node_id,
			..
		} if counterparty_node_id == &node_b_id,
	)));
	assert!(events.iter().any(|e| matches!(
		*e,
		crate::events::Event::ChannelPending {
			ref counterparty_node_id,
			..
		} if counterparty_node_id == &node_c_id,
	)));
}

#[xtest(feature = "_externalize_tests")]
pub fn test_close_in_funding_batch() {
	// This test ensures that if one of the channels
	// in the batch closes, the complete batch will close.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(
		&nodes[0],
		&[(&nodes[1], 100_000, 0, 42, None), (&nodes[2], 200_000, 0, 43, None)],
	);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);

	// Force-close the channel for which we've completed the initial monitor.
	let funding_txo_1 = OutPoint { txid: tx.compute_txid(), index: 0 };
	let funding_txo_2 = OutPoint { txid: tx.compute_txid(), index: 1 };
	let channel_id_1 = ChannelId::v1_from_funding_outpoint(funding_txo_1);
	let channel_id_2 = ChannelId::v1_from_funding_outpoint(funding_txo_2);
	let err = "Channel force-closed".to_string();
	nodes[0].node.force_close_broadcasting_latest_txn(&channel_id_1, &node_b_id, err).unwrap();

	// The monitor should become closed.
	check_added_monitors(&nodes[0], 1);
	{
		let mut monitor_updates = nodes[0].chain_monitor.monitor_updates.lock().unwrap();
		let monitor_updates_1 = monitor_updates.get(&channel_id_1).unwrap();
		assert_eq!(monitor_updates_1.len(), 1);
		assert_eq!(monitor_updates_1[0].updates.len(), 1);
		assert!(matches!(
			monitor_updates_1[0].updates[0],
			ChannelMonitorUpdateStep::ChannelForceClosed { .. }
		));
	}

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError { .. } => (),
		_ => panic!("Unexpected message."),
	}

	// Because the funding was never broadcasted, we should never bother to broadcast the
	// commitment transactions either.
	let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 0);

	// All channels in the batch should close immediately.
	check_closed_events(
		&nodes[0],
		&[
			ExpectedCloseEvent {
				channel_id: Some(channel_id_1),
				discard_funding: true,
				channel_funding_txo: Some(funding_txo_1),
				user_channel_id: Some(42),
				..Default::default()
			},
			ExpectedCloseEvent {
				channel_id: Some(channel_id_2),
				discard_funding: true,
				channel_funding_txo: Some(funding_txo_2),
				user_channel_id: Some(43),
				..Default::default()
			},
		],
	);

	// Ensure the channels don't exist anymore.
	assert!(nodes[0].node.list_channels().is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_batch_funding_close_after_funding_signed() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(
		&nodes[0],
		&[(&nodes[1], 100_000, 0, 42, None), (&nodes[2], 200_000, 0, 43, None)],
	);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// Go through the funding_created and funding_signed flow with node 2.
	nodes[2].node.handle_funding_created(node_a_id, &funding_created_msgs[1]);
	check_added_monitors(&nodes[2], 1);
	expect_channel_pending_event(&nodes[2], &node_a_id);

	let funding_signed_msg =
		get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, node_a_id);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_funding_signed(node_c_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);

	// Force-close the channel for which we've completed the initial monitor.
	let funding_txo_1 = OutPoint { txid: tx.compute_txid(), index: 0 };
	let funding_txo_2 = OutPoint { txid: tx.compute_txid(), index: 1 };
	let channel_id_1 = ChannelId::v1_from_funding_outpoint(funding_txo_1);
	let channel_id_2 = ChannelId::v1_from_funding_outpoint(funding_txo_2);
	let err = "Channel force-closed".to_string();
	nodes[0].node.force_close_broadcasting_latest_txn(&channel_id_1, &node_b_id, err).unwrap();
	check_added_monitors(&nodes[0], 2);
	{
		let mut monitor_updates = nodes[0].chain_monitor.monitor_updates.lock().unwrap();
		let monitor_updates_1 = monitor_updates.get(&channel_id_1).unwrap();
		assert_eq!(monitor_updates_1.len(), 1);
		assert_eq!(monitor_updates_1[0].updates.len(), 1);
		assert!(matches!(
			monitor_updates_1[0].updates[0],
			ChannelMonitorUpdateStep::ChannelForceClosed { .. }
		));
		let monitor_updates_2 = monitor_updates.get(&channel_id_2).unwrap();
		assert_eq!(monitor_updates_2.len(), 1);
		assert_eq!(monitor_updates_2[0].updates.len(), 1);
		assert!(matches!(
			monitor_updates_2[0].updates[0],
			ChannelMonitorUpdateStep::ChannelForceClosed { .. }
		));
	}
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError { .. } => (),
		_ => panic!("Unexpected message."),
	}

	// Because the funding was never broadcasted, we should never bother to broadcast the
	// commitment transactions either.
	let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 0);

	// All channels in the batch should close immediately.
	check_closed_events(
		&nodes[0],
		&[
			ExpectedCloseEvent {
				channel_id: Some(channel_id_1),
				discard_funding: true,
				channel_funding_txo: Some(funding_txo_1),
				user_channel_id: Some(42),
				..Default::default()
			},
			ExpectedCloseEvent {
				channel_id: Some(channel_id_2),
				discard_funding: true,
				channel_funding_txo: Some(funding_txo_2),
				user_channel_id: Some(43),
				..Default::default()
			},
		],
	);

	// Ensure the channels don't exist anymore.
	assert!(nodes[0].node.list_channels().is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_funding_and_commitment_tx_confirm_same_block() {
	// Tests that a node will forget the channel (when it only requires 1 confirmation) if the
	// funding and commitment transaction confirm in the same block.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut min_depth_1_block_cfg = test_default_channel_config();
	min_depth_1_block_cfg.channel_handshake_config.minimum_depth = 1;
	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(min_depth_1_block_cfg.clone()), Some(min_depth_1_block_cfg)],
	);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);
	let chan_id = ChannelId::v1_from_funding_outpoint(chain::transaction::OutPoint {
		txid: funding_tx.compute_txid(),
		index: 0,
	});

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	let commitment_tx = {
		let mon = get_monitor!(nodes[0], chan_id);
		let mut txn = mon.unsafe_get_latest_holder_commitment_txn(&nodes[0].logger);
		assert_eq!(txn.len(), 1);
		txn.pop().unwrap()
	};

	mine_transactions(&nodes[0], &[&funding_tx, &commitment_tx]);
	mine_transactions(&nodes[1], &[&funding_tx, &commitment_tx]);

	let check_msg_events = |node: &Node| {
		let mut msg_events = node.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 3, "{msg_events:?}");
		if let MessageSendEvent::SendChannelReady { .. } = msg_events.remove(0) {
		} else {
			panic!();
		}
		if let MessageSendEvent::HandleError {
			action: msgs::ErrorAction::SendErrorMessage { .. },
			node_id: _,
		} = msg_events.remove(0)
		{
		} else {
			panic!();
		}
		if let MessageSendEvent::BroadcastChannelUpdate { ref msg } = msg_events.remove(0) {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		} else {
			panic!();
		}
	};
	check_msg_events(&nodes[0]);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, false, &[node_b_id], 1_000_000);

	check_msg_events(&nodes[1]);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, false, &[node_a_id], 1_000_000);

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_accept_inbound_channel_errors_queued() {
	// For manually accepted inbound channels, tests that a close error is correctly handled
	// and the channel fails for the initiator.
	let mut config0 = test_default_channel_config();
	let mut config1 = config0.clone();
	config1.channel_handshake_limits.their_to_self_delay = 1000;
	config1.manually_accept_inbound_channels = true;
	config0.channel_handshake_config.our_to_self_delay = 2000;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config0), Some(config1)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			match nodes[1].node.accept_inbound_channel(&temporary_channel_id, &node_a_id, 23, None)
			{
				Err(APIError::ChannelUnavailable { err: _ }) => (),
				_ => panic!(),
			}
		},
		_ => panic!("Unexpected event"),
	}
	assert_eq!(
		get_err_msg(&nodes[1], &node_a_id).channel_id,
		open_channel_msg.common_fields.temporary_channel_id
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_manual_funding_abandon() {
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_config.minimum_depth = 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg.clone()), Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	assert!(nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).is_ok());
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);

	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);
	let (temp_channel_id, _tx, funding_outpoint) =
		create_funding_transaction(&nodes[0], &node_b_id, 100_000, 42);
	nodes[0]
		.node
		.unsafe_manual_funding_transaction_generated(temp_channel_id, node_b_id, funding_outpoint)
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	let err = msgs::ErrorMessage { channel_id: funding_signed.channel_id, data: "".to_string() };
	nodes[0].node.handle_error(node_b_id, &err);

	let close_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(close_events.len(), 2);
	assert!(close_events.iter().any(|ev| matches!(ev, Event::ChannelClosed { .. })));
	assert!(close_events.iter().any(|ev| match ev {
		Event::DiscardFunding { channel_id, funding_info: FundingInfo::OutPoint { outpoint } } => {
			assert_eq!(*channel_id, err.channel_id);
			assert_eq!(*outpoint, funding_outpoint);
			true
		},
		_ => false,
	}));
}

#[xtest(feature = "_externalize_tests")]
pub fn test_funding_signed_event() {
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_config.minimum_depth = 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg.clone()), Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	assert!(nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).is_ok());
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);

	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);
	let (temp_channel_id, tx, funding_outpoint) =
		create_funding_transaction(&nodes[0], &node_b_id, 100_000, 42);
	nodes[0]
		.node
		.unsafe_manual_funding_transaction_generated(temp_channel_id, node_b_id, funding_outpoint)
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed);
	check_added_monitors(&nodes[0], 1);
	let events = &nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		crate::events::Event::FundingTxBroadcastSafe { funding_txo, .. } => {
			assert_eq!(funding_txo.txid, funding_outpoint.txid);
			assert_eq!(funding_txo.vout, funding_outpoint.index.into());
		},
		_ => panic!("Unexpected event"),
	};
	match &events[1] {
		crate::events::Event::ChannelPending { counterparty_node_id, .. } => {
			assert_eq!(node_b_id, *counterparty_node_id);
		},
		_ => panic!("Unexpected event"),
	};

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	let as_channel_ready = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_a_id);
	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
	nodes[0].node.handle_channel_ready(node_b_id, &as_channel_ready);

	expect_channel_ready_event(&nodes[0], &node_b_id);
	expect_channel_ready_event(&nodes[1], &node_a_id);
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}
