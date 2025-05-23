//! Various unit tests covering acceptance of incoming channels and negotiation of channel types.

use lightning_types::features::ChannelTypeFeatures;
use crate::events::Event;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, AcceptChannel, ErrorAction, MessageSendEvent};
use crate::prelude::*;
use crate::util::config::{ChannelHandshakeConfigUpdate, UserConfig, ChannelConfigOverrides};

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
fn test_inbound_zero_fee_commitments_acceptance() {
	let mut zero_fee_cfg = test_default_channel_config();
	zero_fee_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	do_test_manual_inbound_accept_with_override(zero_fee_cfg, None);
}

fn do_test_manual_inbound_accept_with_override(start_cfg: UserConfig,
	config_overrides: Option<ChannelConfigOverrides>) -> AcceptChannel {

	let mut mannual_accept_cfg = start_cfg.clone();
	mannual_accept_cfg.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs,
		&[Some(start_cfg.clone()), Some(start_cfg.clone()), Some(mannual_accept_cfg.clone())]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(nodes[0].node.get_our_node_id(), &open_channel_msg);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	match &msg_events[0] {
		MessageSendEvent::HandleError { node_id, action } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			match action {
				ErrorAction::SendErrorMessage { msg } =>
					assert_eq!(msg.data, "No channels with anchor outputs accepted".to_owned()),
				_ => panic!("Unexpected error action"),
			}
		}
		_ => panic!("Unexpected event"),
	}

	nodes[2].node.handle_open_channel(nodes[0].node.get_our_node_id(), &open_channel_msg);
	let events = nodes[2].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } =>
			nodes[2].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 23, config_overrides).unwrap(),
		_ => panic!("Unexpected event"),
	}
	get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id())
}

#[test]
fn test_anchors_zero_fee_htlc_tx_downgrade() {
	// Tests that if both nodes support anchors, but the remote node does not want to accept
	// anchor channels at the moment, an error it sent to the local node such that it can retry
	// the channel without the anchors feature.
	let mut anchors_config = test_default_channel_config();
	anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	anchors_config.manually_accept_inbound_channels = true;

	do_test_channel_type_downgrade(anchors_config, |features| features.supports_anchors_zero_fee_htlc_tx())
}

#[test]
fn test_zero_fee_commitments_downgrade() {
	// Tests that the local node will retry without zero fee commitments in the case where the
	// remote node supports the feature but does not accept it.
	let mut zero_fee_config = test_default_channel_config();
	zero_fee_config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	zero_fee_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	zero_fee_config.manually_accept_inbound_channels = true;

	do_test_channel_type_downgrade(zero_fee_config, |features| features.supports_anchor_zero_fee_commitments())
}

fn do_test_channel_type_downgrade<F>(user_cfg: UserConfig, start_type_set: F)
	where F: Fn(&ChannelTypeFeatures) -> bool {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(user_cfg.clone()), Some(user_cfg.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let error_message = "Channel force-closed";

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 0, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(start_type_set(open_channel_msg.common_fields.channel_type.as_ref().unwrap()));

	nodes[1].node.handle_open_channel(nodes[0].node.get_our_node_id(), &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.force_close_broadcasting_latest_txn(&temporary_channel_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
		}
		_ => panic!("Unexpected event"),
	}

	let error_msg = get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_error(nodes[1].node.get_our_node_id(), &error_msg);

	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(!start_type_set(open_channel_msg.common_fields.channel_type.as_ref().unwrap()));

	// Since nodes[1] should not have accepted the channel, it should
	// not have generated any events.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
}
