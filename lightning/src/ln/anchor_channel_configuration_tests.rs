use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::types::ChannelId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ErrorAction;
use crate::ln::msgs::ChannelMessageHandler;
use crate::prelude::*;
use crate::util::errors::APIError;
use crate::util::config::ChannelConfigUpdate;

#[test]
fn test_inbound_anchors_manual_acceptance() {
	// Tests that we properly limit inbound channels when we have the manual-channel-acceptance
	// flag set and (sometimes) accept channels as 0conf.
	let mut anchors_cfg = test_default_channel_config();
	anchors_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut anchors_manual_accept_cfg = anchors_cfg.clone();
	anchors_manual_accept_cfg.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs,
		&[Some(anchors_cfg.clone()), Some(anchors_cfg.clone()), Some(anchors_manual_accept_cfg.clone())]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
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

	nodes[2].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	let events = nodes[2].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } =>
			nodes[2].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 23).unwrap(),
		_ => panic!("Unexpected event"),
	}
	get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
}

#[test]
fn test_anchors_zero_fee_htlc_tx_fallback() {
	// Tests that if both nodes support anchors, but the remote node does not want to accept
	// anchor channels at the moment, an error it sent to the local node such that it can retry
	// the channel without the anchors feature.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut anchors_config = test_default_channel_config();
	anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	anchors_config.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(anchors_config.clone()), Some(anchors_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 0, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(open_channel_msg.common_fields.channel_type.as_ref().unwrap().supports_anchors_zero_fee_htlc_tx());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.force_close_broadcasting_latest_txn(&temporary_channel_id, &nodes[0].node.get_our_node_id()).unwrap();
		}
		_ => panic!("Unexpected event"),
	}

	let error_msg = get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &error_msg);

	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(!open_channel_msg.common_fields.channel_type.unwrap().supports_anchors_zero_fee_htlc_tx());

	// Since nodes[1] should not have accepted the channel, it should
	// not have generated any events.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn test_update_channel_config() {
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let mut user_config = test_default_channel_config();
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config), Some(user_config)]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);
	let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
	let channel = &nodes[0].node.list_channels()[0];

	nodes[0].node.update_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &user_config.channel_config).unwrap();
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);

	user_config.channel_config.forwarding_fee_base_msat += 10;
	nodes[0].node.update_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &user_config.channel_config).unwrap();
	assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_base_msat, user_config.channel_config.forwarding_fee_base_msat);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("expected BroadcastChannelUpdate event"),
	}

	nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate::default()).unwrap();
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);

	let new_cltv_expiry_delta = user_config.channel_config.cltv_expiry_delta + 6;
	nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate {
		cltv_expiry_delta: Some(new_cltv_expiry_delta),
		..Default::default()
	}).unwrap();
	assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().cltv_expiry_delta, new_cltv_expiry_delta);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("expected BroadcastChannelUpdate event"),
	}

	let new_fee = user_config.channel_config.forwarding_fee_proportional_millionths + 100;
	nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate {
		forwarding_fee_proportional_millionths: Some(new_fee),
		..Default::default()
	}).unwrap();
	assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().cltv_expiry_delta, new_cltv_expiry_delta);
	assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths, new_fee);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("expected BroadcastChannelUpdate event"),
	}

	// If we provide a channel_id not associated with the peer, we should get an error and no updates
	// should be applied to ensure update atomicity as specified in the API docs.
	let bad_channel_id = ChannelId::v1_from_funding_txid(&[10; 32], 10);
	let current_fee = nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths;
	let new_fee = current_fee + 100;
	assert!(
		matches!(
			nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id, bad_channel_id], &ChannelConfigUpdate {
				forwarding_fee_proportional_millionths: Some(new_fee),
				..Default::default()
			}),
			Err(APIError::ChannelUnavailable { err: _ }),
		)
	);
	// Check that the fee hasn't changed for the channel that exists.
	assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths, current_fee);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
}
