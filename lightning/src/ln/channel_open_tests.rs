// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the channel open process.

use crate::events::Event;
use crate::ln::channelmanager::{MAX_UNFUNDED_CHANNEL_PEERS, MAX_UNFUNDED_CHANS_PER_PEER};
use crate::ln::msgs::{
	AcceptChannel, BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent,
};
use crate::ln::types::ChannelId;
use crate::ln::{functional_test_utils::*, msgs};
use crate::sign::EntropySource;
use crate::util::config::{ChannelConfigOverrides, ChannelHandshakeConfigUpdate, UserConfig};
use crate::util::errors::APIError;
use bitcoin::secp256k1::{PublicKey, SecretKey};
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
