// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use crate::chain;
use crate::chain::{ChannelMonitorUpdateStatus, Confirm, Listen, Watch};
use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::channelmonitor;
use crate::chain::channelmonitor::{CLOSED_CHANNEL_UPDATE_ID, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY};
use crate::chain::transaction::OutPoint;
use crate::sign::{ecdsa::EcdsaChannelSigner, EntropySource, OutputSpender, SignerProvider};
use crate::events::{Event, FundingInfo, MessageSendEvent, MessageSendEventsProvider, PathFailure, PaymentPurpose, ClosureReason, HTLCDestination, PaymentFailureReason};
use crate::ln::types::{ChannelId, PaymentPreimage, PaymentSecret, PaymentHash};
use crate::ln::channel::{CONCURRENT_INBOUND_HTLC_FEE_BUFFER, FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, MIN_AFFORDABLE_HTLC_COUNT, get_holder_selected_channel_reserve_satoshis, OutboundV1Channel, InboundV1Channel, COINBASE_MATURITY, ChannelPhase};
use crate::ln::channelmanager::{self, PaymentId, RAACommitmentOrder, PaymentSendFailure, RecipientOnionFields, BREAKDOWN_TIMEOUT, ENABLE_GOSSIP_TICKS, DISABLE_GOSSIP_TICKS, MIN_CLTV_EXPIRY_DELTA};
use crate::ln::channel::{DISCONNECT_PEER_AWAITING_RESPONSE_TICKS, ChannelError};
use crate::ln::{chan_utils, onion_utils};
use crate::ln::chan_utils::{commitment_tx_base_weight, COMMITMENT_TX_WEIGHT_PER_HTLC, OFFERED_HTLC_SCRIPT_WEIGHT, htlc_success_tx_weight, htlc_timeout_tx_weight, HTLCOutputInCommitment};
use crate::routing::gossip::{NetworkGraph, NetworkUpdate};
use crate::routing::router::{Path, PaymentParameters, Route, RouteHop, get_route, RouteParameters};
use crate::ln::features::{ChannelFeatures, ChannelTypeFeatures, NodeFeatures};
use crate::ln::msgs;
use crate::ln::msgs::{ChannelMessageHandler, RoutingMessageHandler, ErrorAction};
use crate::util::test_channel_signer::TestChannelSigner;
use crate::util::test_utils::{self, TestLogger, WatchtowerPersister};
use crate::util::errors::APIError;
use crate::util::ser::{Writeable, ReadableArgs};
use crate::util::string::UntrustedString;
use crate::util::config::{UserConfig, MaxDustHTLCExposure};

use bitcoin::hash_types::BlockHash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::opcodes;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::OutPoint as BitcoinOutPoint;
use bitcoin::transaction::Version;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey,SecretKey};

use crate::io;
use crate::prelude::*;
use alloc::collections::BTreeSet;
use core::iter::repeat;
use bitcoin::hashes::Hash;
use crate::sync::{Arc, Mutex, RwLock};

use crate::ln::functional_test_utils::*;
use crate::ln::chan_utils::CommitmentTransaction;

use super::channel::UNFUNDED_CHANNEL_AGE_LIMIT_TICKS;

#[test]
fn test_channel_resumption_fail_post_funding() {
	// If we fail to exchange funding with a peer prior to it disconnecting we'll resume the
	// channel open on reconnect, however if we do exchange funding we do not currently support
	// replaying it and here test that the channel closes.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 0, 42, None, None).unwrap();
	let open_chan = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan);
	let accept_chan = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_chan);

	let (temp_chan_id, tx, funding_output) =
		create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);
	let new_chan_id = ChannelId::v1_from_funding_outpoint(funding_output);
	nodes[0].node.funding_transaction_generated(temp_chan_id, nodes[1].node.get_our_node_id(), tx).unwrap();

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	check_closed_events(&nodes[0], &[ExpectedCloseEvent::from_id_reason(new_chan_id, true, ClosureReason::DisconnectedPeer)]);

	// After ddf75afd16 we'd panic on reconnection if we exchanged funding info, so test that
	// explicitly here.
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events(), Vec::new());
}

#[test]
fn test_insane_channel_opens() {
	// Stand up a network of 2 nodes
	use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_limits.max_funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Instantiate channel parameters where we push the maximum msats given our
	// funding satoshis
	let channel_value_sat = 31337; // same as funding satoshis
	let channel_reserve_satoshis = get_holder_selected_channel_reserve_satoshis(channel_value_sat, &cfg);
	let push_msat = (channel_value_sat - channel_reserve_satoshis) * 1000;

	// Have node0 initiate a channel to node1 with aforementioned parameters
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_sat, push_msat, 42, None, None).unwrap();

	// Extract the channel open message from node0 to node1
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	// Test helper that asserts we get the correct error string given a mutator
	// that supposedly makes the channel open message insane
	let insane_open_helper = |expected_error_str: &str, message_mutator: fn(msgs::OpenChannel) -> msgs::OpenChannel| {
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &message_mutator(open_channel_message.clone()));
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		let expected_regex = regex::Regex::new(expected_error_str).unwrap();
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
			match action {
				&ErrorAction::SendErrorMessage { .. } => {
					nodes[1].logger.assert_log_regex("lightning::ln::channelmanager", expected_regex, 1);
				},
				_ => panic!("unexpected event!"),
			}
		} else { assert!(false); }
	};

	use crate::ln::channelmanager::MAX_LOCAL_BREAKDOWN_TIMEOUT;

	// Test all mutations that would make the channel open message insane
	insane_open_helper(format!("Per our config, funding must be at most {}. It was {}", TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1, TOTAL_BITCOIN_SUPPLY_SATOSHIS + 2).as_str(), |mut msg| { msg.common_fields.funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS + 2; msg });
	insane_open_helper(format!("Funding must be smaller than the total bitcoin supply. It was {}", TOTAL_BITCOIN_SUPPLY_SATOSHIS).as_str(), |mut msg| { msg.common_fields.funding_satoshis = TOTAL_BITCOIN_SUPPLY_SATOSHIS; msg });

	insane_open_helper("Bogus channel_reserve_satoshis", |mut msg| { msg.channel_reserve_satoshis = msg.common_fields.funding_satoshis + 1; msg });

	insane_open_helper(r"push_msat \d+ was larger than channel amount minus reserve \(\d+\)", |mut msg| { msg.push_msat = (msg.common_fields.funding_satoshis - msg.channel_reserve_satoshis) * 1000 + 1; msg });

	insane_open_helper("Peer never wants payout outputs?", |mut msg| { msg.common_fields.dust_limit_satoshis = msg.common_fields.funding_satoshis + 1 ; msg });

	insane_open_helper(r"Minimum htlc value \(\d+\) was larger than full channel value \(\d+\)", |mut msg| { msg.common_fields.htlc_minimum_msat = (msg.common_fields.funding_satoshis - msg.channel_reserve_satoshis) * 1000; msg });

	insane_open_helper("They wanted our payments to be delayed by a needlessly long period", |mut msg| { msg.common_fields.to_self_delay = MAX_LOCAL_BREAKDOWN_TIMEOUT + 1; msg });

	insane_open_helper("0 max_accepted_htlcs makes for a useless channel", |mut msg| { msg.common_fields.max_accepted_htlcs = 0; msg });

	insane_open_helper("max_accepted_htlcs was 484. It must not be larger than 483", |mut msg| { msg.common_fields.max_accepted_htlcs = 484; msg });
}

#[test]
fn test_funding_exceeds_no_wumbo_limit() {
	// Test that if a peer does not support wumbo channels, we'll refuse to open a wumbo channel to
	// them.
	use crate::ln::channel::MAX_FUNDING_SATOSHIS_NO_WUMBO;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	*node_cfgs[1].override_init_features.borrow_mut() = Some(channelmanager::provided_init_features(&test_default_channel_config()).clear_wumbo());
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	match nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), MAX_FUNDING_SATOSHIS_NO_WUMBO + 1, 0, 42, None, None) {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(format!("funding_value must not exceed {}, it was {}", MAX_FUNDING_SATOSHIS_NO_WUMBO, MAX_FUNDING_SATOSHIS_NO_WUMBO + 1), err);
		},
		_ => panic!()
	}
}

fn do_test_counterparty_no_reserve(send_from_initiator: bool) {
	// A peer providing a channel_reserve_satoshis of 0 (or less than our dust limit) is insecure,
	// but only for them. Because some LSPs do it with some level of trust of the clients (for a
	// substantial UX improvement), we explicitly allow it. Because it's unlikely to happen often
	// in normal testing, we test it explicitly here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let default_config = UserConfig::default();

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let mut push_amt = 100_000_000;
	let feerate_per_kw = 253;
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	push_amt -= feerate_per_kw as u64 * (commitment_tx_base_weight(&channel_type_features) + 4 * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000 * 1000;
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, if send_from_initiator { 0 } else { push_amt }, 42, None, None).unwrap();
	let mut open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	if !send_from_initiator {
		open_channel_message.channel_reserve_satoshis = 0;
		open_channel_message.common_fields.max_htlc_value_in_flight_msat = 100_000_000;
	}
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_message);

	// Extract the channel accept message from node1 to node0
	let mut accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	if send_from_initiator {
		accept_channel_message.channel_reserve_satoshis = 0;
		accept_channel_message.common_fields.max_htlc_value_in_flight_msat = 100_000_000;
	}
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel_message);
	{
		let sender_node = if send_from_initiator { &nodes[1] } else { &nodes[0] };
		let counterparty_node = if send_from_initiator { &nodes[0] } else { &nodes[1] };
		let mut sender_node_per_peer_lock;
		let mut sender_node_peer_state_lock;

		let channel_phase = get_channel_ref!(sender_node, counterparty_node, sender_node_per_peer_lock, sender_node_peer_state_lock, temp_channel_id);
		match channel_phase {
			ChannelPhase::UnfundedInboundV1(_) | ChannelPhase::UnfundedOutboundV1(_) => {
				let chan_context = channel_phase.context_mut();
				chan_context.holder_selected_channel_reserve_satoshis = 0;
				chan_context.holder_max_htlc_value_in_flight_msat = 100_000_000;
			},
			_ => assert!(false),
		}
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

#[test]
fn test_counterparty_no_reserve() {
	do_test_counterparty_no_reserve(true);
	do_test_counterparty_no_reserve(false);
}

#[test]
fn test_async_inbound_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

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
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 40000);
	nodes[1].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg); // (2)
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	// deliver(1), generate (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// nodes[1] is awaiting nodes[0] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack); // deliver (2)
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_update.update_add_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fulfill_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_malformed_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fee.is_none()); // (4)
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack); // deliver (3)
	let as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_update.update_add_htlcs.is_empty()); // (5)
	assert!(as_update.update_fulfill_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_malformed_htlcs.is_empty()); // (5)
	assert!(as_update.update_fee.is_none()); // (5)
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed); // deliver (4)
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// only (6) so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update.commitment_signed); // deliver (5)
	let bs_second_revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke);
	check_added_monitors!(nodes[0], 1);

	let events_2 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PendingHTLCsForwardable {..} => {}, // If we actually processed we'd receive the payment
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke); // deliver (6)
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_unordered_raa() {
	// Just the intro to the previous test followed by an out-of-order RAA (which caused a
	// crash in an earlier version of the update_fee patch)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	// First nodes[0] generates an update_fee
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let update_msg = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, .. }, .. } => {
			update_fee.as_ref()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 40000);
	nodes[1].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg); // (2)
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg); // deliver (2)
	check_added_monitors!(nodes[1], 1);

	// We can't continue, sadly, because our (1) now has a bogus signature
}

#[test]
fn test_multi_flight_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
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
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg_1, commitment_signed_1) = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref().unwrap(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	// Deliver first update_fee/commitment_signed pair, generating (1) and (2):
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg_1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed_1);
	let (bs_revoke_msg, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

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

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2);

	update_msg_2.feerate_per_kw = (initial_feerate + 40) as u32;
	// Deliver (3)
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2);

	// Deliver (1), generating (3) and (4)
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_msg);
	let as_second_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	assert!(as_second_update.update_add_htlcs.is_empty());
	assert!(as_second_update.update_fulfill_htlcs.is_empty());
	assert!(as_second_update.update_fail_htlcs.is_empty());
	assert!(as_second_update.update_fail_malformed_htlcs.is_empty());
	// Check that the update_fee newly generated matches what we delivered:
	assert_eq!(as_second_update.update_fee.as_ref().unwrap().channel_id, update_msg_2.channel_id);
	assert_eq!(as_second_update.update_fee.as_ref().unwrap().feerate_per_kw, update_msg_2.feerate_per_kw);

	// Deliver (2) commitment_signed
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed);
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Delever (4)
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update.commitment_signed);
	let (bs_second_revoke, bs_second_commitment) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment);
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
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

	if steps & 0b1000_0000 != 0{
		let block = create_dummy_block(nodes[0].best_block_hash(), 42, Vec::new());
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
	}

	if steps & 0x0f == 0 { return; }
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	if steps & 0x0f == 1 { return; }
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	if steps & 0x0f == 2 { return; }
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);

	if steps & 0x0f == 3 { return; }
	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors!(nodes[0], 0);
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	if steps & 0x0f == 4 { return; }
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

	if steps & 0x0f == 5 { return; }
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 0);

	if steps & 0x0f == 6 { return; }
	create_chan_between_nodes_with_value_confirm_first(&nodes[0], &nodes[1], &tx, 2);

	if steps & 0x0f == 7 { return; }
	confirm_transaction_at(&nodes[0], &tx, 2);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);
	create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
	expect_channel_ready_event(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_sanity_on_in_flight_opens() {
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

#[test]
fn test_update_fee_vanilla() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 25;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_that_funder_cannot_afford() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_value = 5000;
	let push_sats = 700;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, push_sats * 1000);
	let channel_id = chan.2;
	let secp_ctx = Secp256k1::new();
	let default_config = UserConfig::default();
	let bs_channel_reserve_sats = get_holder_selected_channel_reserve_satoshis(channel_value, &default_config);

	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	// Calculate the maximum feerate that A can afford. Note that we don't send an update_fee
	// CONCURRENT_INBOUND_HTLC_FEE_BUFFER HTLCs before actually running out of local balance, so we
	// calculate two different feerates here - the expected local limit as well as the expected
	// remote limit.
	let feerate = ((channel_value - bs_channel_reserve_sats - push_sats) * 1000 / (commitment_tx_base_weight(&channel_type_features) + CONCURRENT_INBOUND_HTLC_FEE_BUFFER as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC)) as u32;
	let non_buffer_feerate = ((channel_value - bs_channel_reserve_sats - push_sats) * 1000 / commitment_tx_base_weight(&channel_type_features)) as u32;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = feerate;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);
	let update_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg.update_fee.unwrap());

	commitment_signed_dance!(nodes[1], nodes[0], update_msg.commitment_signed, false);

	// Confirm that the new fee based on the last local commitment txn is what we expected based on the feerate set above.
	{
		let commitment_tx = get_local_commitment_txn!(nodes[1], channel_id)[0].clone();

		//We made sure neither party's funds are below the dust limit and there are no HTLCs here
		assert_eq!(commitment_tx.output.len(), 2);
		let total_fee: u64 = commit_tx_fee_msat(feerate, 0, &channel_type_features) / 1000;
		let mut actual_fee = commitment_tx.output.iter().fold(0, |acc, output| acc + output.value.to_sat());
		actual_fee = channel_value - actual_fee;
		assert_eq!(total_fee, actual_fee);
	}

	{
		// Increment the feerate by a small constant, accounting for rounding errors
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 4;
	}
	nodes[0].node.timer_tick_occurred();
	nodes[0].logger.assert_log("lightning::ln::channel", format!("Cannot afford to send new feerate at {}", feerate + 4), 1);
	check_added_monitors!(nodes[0], 0);

	const INITIAL_COMMITMENT_NUMBER: u64 = 281474976710654;

	// Get the TestChannelSigner for each channel, which will be used to (1) get the keys
	// needed to sign the new commitment tx and (2) sign the new commitment tx.
	let (local_revocation_basepoint, local_htlc_basepoint, local_funding) = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let local_chan = chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let chan_signer = local_chan.get_signer();
		let pubkeys = chan_signer.as_ref().pubkeys();
		(pubkeys.revocation_basepoint, pubkeys.htlc_basepoint,
		 pubkeys.funding_pubkey)
	};
	let (remote_delayed_payment_basepoint, remote_htlc_basepoint, remote_point, remote_funding) = {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		let remote_chan = chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let chan_signer = remote_chan.get_signer();
		let pubkeys = chan_signer.as_ref().pubkeys();
		(pubkeys.delayed_payment_basepoint, pubkeys.htlc_basepoint,
		 chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, &secp_ctx).unwrap(),
		 pubkeys.funding_pubkey)
	};

	// Assemble the set of keys we can use for signatures for our commitment_signed message.
	let commit_tx_keys = chan_utils::TxCreationKeys::derive_new(&secp_ctx, &remote_point, &remote_delayed_payment_basepoint,
		&remote_htlc_basepoint, &local_revocation_basepoint, &local_htlc_basepoint);

	let res = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let local_chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let local_chan = local_chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let local_chan_signer = local_chan.get_signer();
		let mut htlcs: Vec<(HTLCOutputInCommitment, ())> = vec![];
		let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			INITIAL_COMMITMENT_NUMBER - 1,
			push_sats,
			channel_value - push_sats - commit_tx_fee_msat(non_buffer_feerate + 4, 0, &channel_type_features) / 1000,
			local_funding, remote_funding,
			commit_tx_keys.clone(),
			non_buffer_feerate + 4,
			&mut htlcs,
			&local_chan.context.channel_transaction_parameters.as_counterparty_broadcastable()
		);
		local_chan_signer.as_ecdsa().unwrap().sign_counterparty_commitment(&commitment_tx, Vec::new(), Vec::new(), &secp_ctx).unwrap()
	};

	let commit_signed_msg = msgs::CommitmentSigned {
		channel_id: chan.2,
		signature: res.0,
		htlc_signatures: res.1,
		batch: None,
		#[cfg(taproot)]
		partial_signature_with_nonce: None,
	};

	let update_fee = msgs::UpdateFee {
		channel_id: chan.2,
		feerate_per_kw: non_buffer_feerate + 4,
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_fee);

	//While producing the commitment_signed response after handling a received update_fee request the
	//check to see if the funder, who sent the update_fee request, can afford the new fee (funder_balance >= fee+channel_reserve)
	//Should produce and error.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commit_signed_msg);
	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Funding remote cannot afford proposed new fee", 3);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: String::from("Funding remote cannot afford proposed new fee") },
		[nodes[0].node.get_our_node_id()], channel_value);
}

#[test]
fn test_update_fee_with_fundee_update_add_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 800000);

	// nothing happens since node[1] is in AwaitingRemoteRevoke
	nodes[1].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 0);
		added_monitors.clear();
	}
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	// node[1] has nothing to do

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	check_added_monitors!(nodes[1], 1);
	// AwaitingRemoteRevoke ends here

	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(commitment_update.update_add_htlcs.len(), 1);
	assert_eq!(commitment_update.update_fulfill_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_malformed_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fee.is_none(), true);

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &commitment_update.update_add_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (revoke, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[0]);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { .. } => { },
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[1], &vec!(&nodes[0])[..], our_payment_preimage);

	send_payment(&nodes[1], &vec!(&nodes[0])[..], 800000);
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 800000);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	check_closed_event!(nodes[0], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
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
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// Generate (2) and (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed_0) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// Deliver (2):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Create and deliver (4)...
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = feerate + 30;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);
	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// ... creating (5)
	let revoke_msg = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Handle (3), creating (6):
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed_0);
	check_added_monitors!(nodes[0], 1);
	let revoke_msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Deliver (5):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Deliver (6), creating (7):
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg_0);
	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(commitment_update.update_add_htlcs.is_empty());
	assert!(commitment_update.update_fulfill_htlcs.is_empty());
	assert!(commitment_update.update_fail_htlcs.is_empty());
	assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
	assert!(commitment_update.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	// Deliver (7)
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(get_feerate!(nodes[0], nodes[1], channel_id), feerate + 30);
	assert_eq!(get_feerate!(nodes[1], nodes[0], channel_id), feerate + 30);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	check_closed_event!(nodes[0], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn fake_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that payments get routed and transactions broadcast in semi-reasonable ways.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);

	// Send some more payments
	send_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 1000000);
	send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1], &nodes[0])[..], 1000000);
	send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1])[..], 1000000);

	// Test failure packets
	let payment_hash_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 1000000).1;
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], payment_hash_1);

	// Add a new channel that skips 3
	let chan_4 = create_announced_chan_between_nodes(&nodes, 1, 3);

	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 1000000);
	send_payment(&nodes[2], &vec!(&nodes[3])[..], 1000000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);

	// Do some rebalance loop payments, simultaneously
	let mut hops = Vec::with_capacity(3);
	hops.push(RouteHop {
		pubkey: nodes[2].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_2.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_3.0.contents.cltv_expiry_delta as u32,
		maybe_announced_channel: true,
	});
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_4.1.contents.cltv_expiry_delta as u32,
		maybe_announced_channel: true,
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		node_features: nodes[1].node.node_features(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		channel_features: nodes[1].node.channel_features(),
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
		maybe_announced_channel: true,
	});
	hops[1].fee_msat = chan_4.1.contents.fee_base_msat as u64 + chan_4.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.0.contents.fee_base_msat as u64 + chan_3.0.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_preimage_1 = send_along_route(&nodes[1],
		Route { paths: vec![Path { hops, blinded_tail: None }], route_params: None },
			&vec!(&nodes[2], &nodes[3], &nodes[1])[..], 1000000).0;

	let mut hops = Vec::with_capacity(3);
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_3.1.contents.cltv_expiry_delta as u32,
		maybe_announced_channel: true,
	});
	hops.push(RouteHop {
		pubkey: nodes[2].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_2.1.contents.cltv_expiry_delta as u32,
		maybe_announced_channel: true,
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		node_features: nodes[1].node.node_features(),
		short_channel_id: chan_2.0.contents.short_channel_id,
		channel_features: nodes[1].node.channel_features(),
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
		maybe_announced_channel: true,
	});
	hops[1].fee_msat = chan_2.1.contents.fee_base_msat as u64 + chan_2.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.1.contents.fee_base_msat as u64 + chan_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_hash_2 = send_along_route(&nodes[1],
		Route { paths: vec![Path { hops, blinded_tail: None }], route_params: None },
			&vec!(&nodes[3], &nodes[2], &nodes[1])[..], 1000000).1;

	// Claim the rebalances...
	fail_payment(&nodes[1], &vec!(&nodes[3], &nodes[2], &nodes[1])[..], payment_hash_2);
	claim_payment(&nodes[1], &vec!(&nodes[2], &nodes[3], &nodes[1])[..], payment_preimage_1);

	// Close down the channels...
	close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
	check_closed_event!(nodes[0], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, false);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[2].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[2], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	close_channel(&nodes[2], &nodes[3], &chan_3.2, chan_3.3, true);
	check_closed_event!(nodes[2], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[3].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[3], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[2].node.get_our_node_id()], 100000);
	close_channel(&nodes[1], &nodes[3], &chan_4.2, chan_4.3, false);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[3].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[3], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn holding_cell_htlc_counting() {
	// Tests that HTLCs in the holding cell count towards the pending HTLC limits on outbound HTLCs
	// to ensure we don't end up with HTLCs sitting around in our holding cell for several
	// commitment dance rounds.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
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
	assert_eq!(initial_payment_event.node_id, nodes[2].node.get_our_node_id());

	// There is now one HTLC in an outbound commitment transaction and (OUR_MAX_HTLCS - 1) HTLCs in
	// the holding cell waiting on B's RAA to send. At this point we should not be able to add
	// another HTLC.
	{
		unwrap_send_err!(nodes[1].node.send_payment_with_route(route, payment_hash_1,
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
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
	// fails), the second will process the resulting failure and fail the HTLC backward.
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	check_added_monitors!(nodes[1], 1);

	let bs_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_fail_updates.commitment_signed, false, true);

	expect_payment_failed_with_update!(nodes[0], payment_hash_2, false, chan_2.0.contents.short_channel_id, false);

	// Now forward all the pending HTLCs and claim them back
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &initial_payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &initial_payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);

	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	let as_updates = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	for ref update in as_updates.update_add_htlcs.iter() {
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), update);
	}
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);
	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_final_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_final_raa);
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

#[test]
fn duplicate_htlc_test() {
	// Test that we accept duplicate payment_hash HTLCs across the network and that
	// claiming/failing them are all separate and don't affect each other
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let mut nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	// Create some initial channels to route via 3 to 4/5 from 0/1/2
	create_announced_chan_between_nodes(&nodes, 0, 3);
	create_announced_chan_between_nodes(&nodes, 1, 3);
	create_announced_chan_between_nodes(&nodes, 2, 3);
	create_announced_chan_between_nodes(&nodes, 3, 4);
	create_announced_chan_between_nodes(&nodes, 3, 5);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], 1000000);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[1], &vec!(&nodes[3])[..], 1000000).0, payment_preimage);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], 1000000).0, payment_preimage);

	claim_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], payment_preimage);
	fail_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], payment_hash);
	claim_payment(&nodes[1], &vec!(&nodes[3])[..], payment_preimage);
}

#[test]
fn test_duplicate_htlc_different_direction_onchain() {
	// Test that ChannelMonitor doesn't generate 2 preimage txn
	// when we have 2 HTLCs with same preimage that go across a node
	// in opposite directions, even with the same payment secret.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 900_000);

	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[0], 800_000);
	let node_a_payment_secret = nodes[0].node.create_inbound_payment_for_hash(payment_hash, None, 7200, None).unwrap();
	send_along_route_with_secret(&nodes[1], route, &[&[&nodes[0]]], 800_000, payment_hash, node_a_payment_secret);

	// Provide preimage to node 0 by claiming payment
	nodes[0].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[0], payment_hash, 800_000);
	check_added_monitors!(nodes[0], 1);

	// Broadcast node 1 commitment txn
	let remote_txn = get_local_commitment_txn!(nodes[1], chan_1.2);

	assert_eq!(remote_txn[0].output.len(), 4); // 1 local, 1 remote, 1 htlc inbound, 1 htlc outbound
	let mut has_both_htlcs = 0; // check htlcs match ones committed
	for outp in remote_txn[0].output.iter() {
		if outp.value.to_sat() == 800_000 / 1000 {
			has_both_htlcs += 1;
		} else if outp.value.to_sat() == 900_000 / 1000 {
			has_both_htlcs += 1;
		}
	}
	assert_eq!(has_both_htlcs, 2);

	mine_transaction(&nodes[0], &remote_txn[0]);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let claim_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(claim_txn.len(), 3);

	check_spends!(claim_txn[0], remote_txn[0]); // Immediate HTLC claim with preimage
	check_spends!(claim_txn[1], remote_txn[0]);
	check_spends!(claim_txn[2], remote_txn[0]);
	let preimage_tx = &claim_txn[0];
	let (preimage_bump_tx, timeout_tx) = if claim_txn[1].input[0].previous_output == preimage_tx.input[0].previous_output {
		(&claim_txn[1], &claim_txn[2])
	} else {
		(&claim_txn[2], &claim_txn[1])
	};

	assert_eq!(preimage_tx.input.len(), 1);
	assert_eq!(preimage_bump_tx.input.len(), 1);

	assert_eq!(preimage_tx.input.len(), 1);
	assert_eq!(preimage_tx.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC 1 <--> 0, preimage tx
	assert_eq!(remote_txn[0].output[preimage_tx.input[0].previous_output.vout as usize].value.to_sat(), 800);

	assert_eq!(timeout_tx.input.len(), 1);
	assert_eq!(timeout_tx.input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // HTLC 0 <--> 1, timeout tx
	check_spends!(timeout_tx, remote_txn[0]);
	assert_eq!(remote_txn[0].output[timeout_tx.input[0].previous_output.vout as usize].value.to_sat(), 900);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3);
	for e in events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::DisconnectPeer { ref msg } } => {
				assert_eq!(node_id, nodes[1].node.get_our_node_id());
				assert_eq!(msg.as_ref().unwrap().data, "Channel closed because commitment or closing transaction was confirmed on chain.");
			},
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_malformed_htlcs.is_empty());
				assert_eq!(nodes[1].node.get_our_node_id(), *node_id);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_basic_channel_reserve() {
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
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).err().unwrap();
	match err {
		PaymentSendFailure::AllFailedResendSafe(ref fails) => {
			if let &APIError::ChannelUnavailable { .. } = &fails[0] {}
			else { panic!("Unexpected error variant"); }
		},
		_ => panic!("Unexpected error variant"),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	send_payment(&nodes[0], &vec![&nodes[1]], max_can_send);
}

#[test]
fn test_fee_spike_violation_fails_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 3460000);
	route.paths[0].hops[0].fee_msat += 1;
	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).expect("RNG is bad!");

	let cur_height = nodes[1].node.best_block.read().unwrap().height + 1;

	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0],
		3460001, &recipient_onion_fields, cur_height, &None).unwrap();
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

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);

	// Now manually create the commitment_signed message corresponding to the update_add
	// nodes[0] just sent. In the code for construction of this message, "local" refers
	// to the sender of the message, and "remote" refers to the receiver.

	let feerate_per_kw = get_feerate!(nodes[0], nodes[1], chan.2);

	const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

	// Get the TestChannelSigner for each channel, which will be used to (1) get the keys
	// needed to sign the new commitment tx and (2) sign the new commitment tx.
	let (local_revocation_basepoint, local_htlc_basepoint, local_secret, next_local_point, local_funding) = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let local_chan = chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let chan_signer = local_chan.get_signer();
		// Make the signer believe we validated another commitment, so we can release the secret
		chan_signer.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;

		let pubkeys = chan_signer.as_ref().pubkeys();
		(pubkeys.revocation_basepoint, pubkeys.htlc_basepoint,
		 chan_signer.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER).unwrap(),
		 chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 2, &secp_ctx).unwrap(),
		 chan_signer.as_ref().pubkeys().funding_pubkey)
	};
	let (remote_delayed_payment_basepoint, remote_htlc_basepoint, remote_point, remote_funding) = {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		let remote_chan = chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let chan_signer = remote_chan.get_signer();
		let pubkeys = chan_signer.as_ref().pubkeys();
		(pubkeys.delayed_payment_basepoint, pubkeys.htlc_basepoint,
		 chan_signer.as_ref().get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, &secp_ctx).unwrap(),
		 chan_signer.as_ref().pubkeys().funding_pubkey)
	};

	// Assemble the set of keys we can use for signatures for our commitment_signed message.
	let commit_tx_keys = chan_utils::TxCreationKeys::derive_new(&secp_ctx, &remote_point, &remote_delayed_payment_basepoint,
		&remote_htlc_basepoint, &local_revocation_basepoint, &local_htlc_basepoint);

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
		let local_chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let local_chan = local_chan_lock.channel_by_id.get(&chan.2).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap();
		let local_chan_signer = local_chan.get_signer();
		let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			commitment_number,
			95000,
			local_chan_balance,
			local_funding, remote_funding,
			commit_tx_keys.clone(),
			feerate_per_kw,
			&mut vec![(accepted_htlc_info, ())],
			&local_chan.context.channel_transaction_parameters.as_counterparty_broadcastable()
		);
		local_chan_signer.as_ecdsa().unwrap().sign_counterparty_commitment(&commitment_tx, Vec::new(), Vec::new(), &secp_ctx).unwrap()
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
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commit_signed_msg);
	let _ = nodes[1].node.get_and_clear_pending_msg_events();

	// Send the RAA to nodes[1].
	let raa_msg = msgs::RevokeAndACK {
		channel_id: chan.2,
		per_commitment_secret: local_secret,
		next_per_commitment_point: next_local_point,
		#[cfg(taproot)]
		next_local_nonce: None,
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa_msg);

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

	check_added_monitors!(nodes[1], 2);
}

#[test]
fn test_chan_reserve_violation_outbound_htlc_inbound_chan() {
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
	unwrap_send_err!(nodes[1].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_chan_reserve_violation_inbound_htlc_outbound_channel() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
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
	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0],
		700_000, &recipient_onion_fields, cur_height, &None).unwrap();
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

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &msg);
	// Check that the payment failed and the channel is closed in response to the malicious UpdateAdd.
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager", "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value", 3);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value");
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value".to_string() },
		[nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_chan_reserve_dust_inbound_htlcs_outbound_chan() {
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
	unwrap_send_err!(nodes[1].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
}

#[test]
fn test_chan_init_feerate_unaffordability() {
	// Test that we will reject channel opens which do not leave enough to pay for any HTLCs due to
	// channel reserve and feerate requirements.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let feerate_per_kw = *chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let default_config = UserConfig::default();
	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	// Set the push_msat amount such that nodes[0] will not be able to afford to add even a single
	// HTLC.
	let mut push_amt = 100_000_000;
	push_amt -= commit_tx_fee_msat(feerate_per_kw, MIN_AFFORDABLE_HTLC_COUNT as u64, &channel_type_features);
	assert_eq!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, push_amt + 1, 42, None, None).unwrap_err(),
		APIError::APIMisuseError { err: "Funding amount (356) can't even pay fee for initial commitment transaction fee of 357.".to_string() });

	// During open, we don't have a "counterparty channel reserve" to check against, so that
	// requirement only comes into play on the open_channel handling side.
	push_amt -= get_holder_selected_channel_reserve_satoshis(100_000, &default_config) * 1000;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, push_amt, 42, None, None).unwrap();
	let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel_msg.push_msat += 1;
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
			assert_eq!(msg.data, "Insufficient funding amount for initial reserve");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_chan_reserve_dust_inbound_htlcs_inbound_chan() {
	// Test that if we receive many dust HTLCs over an inbound channel, they don't count when
	// calculating our counterparty's commitment transaction fee (this was previously broken).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 98000000);

	let payment_amt = 46000; // Dust amount
	// In the previous code, these first four payments would succeed.
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);

	// Then these next 5 would be interpreted by nodes[1] as violating the fee spike buffer.
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);

	// And this last payment previously resulted in nodes[1] closing on its inbound-channel
	// counterparty, because it counted all the previous dust HTLCs against nodes[0]'s commitment
	// transaction fee and therefore perceived this next payment as a channel reserve violation.
	route_payment(&nodes[0], &[&nodes[1]], payment_amt);
}

#[test]
fn test_chan_reserve_violation_inbound_htlc_inbound_chan() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let _ = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 95000000);

	let feemsat = 239;
	let total_routing_fee_msat = (nodes.len() - 2) as u64 * feemsat;
	let chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);

	// Add a 2* and +1 for the fee spike reserve.
	let commit_tx_fee_2_htlc = 2*commit_tx_fee_msat(feerate, 2 + 1, &channel_type_features);
	let recv_value_1 = (chan_stat.value_to_self_msat - chan_stat.channel_reserve_msat - total_routing_fee_msat - commit_tx_fee_2_htlc)/2;
	let amt_msat_1 = recv_value_1 + total_routing_fee_msat;

	// Add a pending HTLC.
	let (route_1, our_payment_hash_1, _, our_payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat_1);
	let payment_event_1 = {
		nodes[0].node.send_payment_with_route(route_1.clone(), our_payment_hash_1,
			RecipientOnionFields::secret_only(our_payment_secret_1), PaymentId(our_payment_hash_1.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]);

	// Attempt to trigger a channel reserve violation --> payment failure.
	let commit_tx_fee_2_htlcs = commit_tx_fee_msat(feerate, 2, &channel_type_features);
	let recv_value_2 = chan_stat.value_to_self_msat - amt_msat_1 - chan_stat.channel_reserve_msat - total_routing_fee_msat - commit_tx_fee_2_htlcs + 1;
	let amt_msat_2 = recv_value_2 + total_routing_fee_msat;
	let mut route_2 = route_1.clone();
	route_2.paths[0].hops.last_mut().unwrap().fee_msat = amt_msat_2;

	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
	let cur_height = nodes[0].node.best_block.read().unwrap().height + 1;
	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route_2.paths[0], &session_priv).unwrap();
	let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(
		&route_2.paths[0], recv_value_2, &recipient_onion_fields, cur_height, &None).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &our_payment_hash_1).unwrap();
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 1,
		amount_msat: htlc_msat + 1,
		payment_hash: our_payment_hash_1,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
		skimmed_fee_msat: None,
		blinding_point: None,
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);
	// Check that the payment failed and the channel is closed in response to the malicious UpdateAdd.
	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Remote HTLC add would put them under remote reserve value", 3);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data, "Remote HTLC add would put them under remote reserve value");
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: "Remote HTLC add would put them under remote reserve value".to_string() },
		[nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_inbound_outbound_capacity_is_not_zero() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let channels0 = node_chanmgrs[0].list_channels();
	let channels1 = node_chanmgrs[1].list_channels();
	let default_config = UserConfig::default();
	assert_eq!(channels0.len(), 1);
	assert_eq!(channels1.len(), 1);

	let reserve = get_holder_selected_channel_reserve_satoshis(100_000, &default_config);
	assert_eq!(channels0[0].inbound_capacity_msat, 95000000 - reserve*1000);
	assert_eq!(channels1[0].outbound_capacity_msat, 95000000 - reserve*1000);

	assert_eq!(channels0[0].outbound_capacity_msat, 100000 * 1000 - 95000000 - reserve*1000);
	assert_eq!(channels1[0].inbound_capacity_msat, 100000 * 1000 - 95000000 - reserve*1000);
}

fn commit_tx_fee_msat(feerate: u32, num_htlcs: u64, channel_type_features: &ChannelTypeFeatures) -> u64 {
	(commitment_tx_base_weight(channel_type_features) + num_htlcs * COMMITMENT_TX_WEIGHT_PER_HTLC) * feerate as u64 / 1000 * 1000
}

#[test]
fn test_channel_reserve_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 239;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config.clone()), Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 190000, 1001);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 190000, 1001);

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
		let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
			.with_bolt11_features(nodes[2].node.bolt11_invoice_features()).unwrap().with_max_channel_saturation_power_of_half(0);
		let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, recv_value_0);
		route.paths[0].hops.last_mut().unwrap().fee_msat += 1;
		assert!(route.paths[0].hops.iter().rev().skip(1).all(|h| h.fee_msat == feemsat));

		unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
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

		let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
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
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]);

	// channel reserve test with htlc pending output > 0
	let recv_value_2 = stat01.value_to_self_msat - amt_msat_1 - stat01.channel_reserve_msat - total_fee_msat - commit_tx_fee_2_htlcs;
	{
		let mut route = route_1.clone();
		route.paths[0].hops.last_mut().unwrap().fee_msat = recv_value_2 + 1;
		let (_, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(nodes[2]);
		unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
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
		unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
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
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event_1.commitment_msg);
	let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// the pending htlc should be promoted to committed
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack);
	check_added_monitors!(nodes[0], 1);
	let commitment_update_2 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_11 = expect_forward!(nodes[1]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_11.msgs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event_11.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[2]);
	expect_payment_claimable!(nodes[2], our_payment_hash_1, our_payment_secret_1, recv_value_1);

	// flush the htlcs in the holding cell
	assert_eq!(commitment_update_2.update_add_htlcs.len(), 2);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[0]);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[1]);
	commitment_signed_dance!(nodes[1], nodes[0], &commitment_update_2.commitment_signed, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_3 = expect_forward!(nodes[1]);
	assert_eq!(payment_event_3.msgs.len(), 2);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[0]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[1]);

	commitment_signed_dance!(nodes[2], nodes[1], &payment_event_3.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, amount_msat, receiver_node_id, via_channel_id, .. } => {
			assert_eq!(our_payment_hash_21, *payment_hash);
			assert_eq!(recv_value_21, amount_msat);
			assert_eq!(nodes[2].node.get_our_node_id(), receiver_node_id.unwrap());
			assert_eq!(via_channel_id, Some(chan_2.2));
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
		Event::PaymentClaimable { ref payment_hash, ref purpose, amount_msat, receiver_node_id, via_channel_id, .. } => {
			assert_eq!(our_payment_hash_22, *payment_hash);
			assert_eq!(recv_value_22, amount_msat);
			assert_eq!(nodes[2].node.get_our_node_id(), receiver_node_id.unwrap());
			assert_eq!(via_channel_id, Some(chan_2.2));
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

#[test]
fn channel_reserve_in_flight_removes() {
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
	let bs_removes = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	// This claim goes in B's holding cell, allowing us to have a pending B->A RAA which does not
	// remove the second HTLC when we send the HTLC back from B to A.
	nodes[1].node.claim_funds(payment_preimage_2);
	expect_payment_claimed!(nodes[1], payment_hash_2, 20_000);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_removes.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_removes.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_1.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_1.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	// B is already AwaitingRAA, so cant generate a CS here
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	// The second HTLCis removed, but as A is in AwaitingRAA it can't generate a CS here, so the
	// RAA that B generated above doesn't fully resolve the second HTLC from A's point of view.
	// However, the RAA A generates here *does* fully resolve the HTLC from B's point of view (as A
	// can no longer broadcast a commitment transaction with it and B has the preimage so can go
	// on-chain as necessary).
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_cs.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent(&nodes[0], payment_preimage_2, None, false, false);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash_3, payment_secret_3, 100000);

	// Note that as this RAA was generated before the delivery of the update_fulfill it shouldn't
	// resolve the second HTLC from A's point of view.
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

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

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_2.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_2.commitment_msg);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Now just resolve all the outstanding messages/HTLCs for completeness...

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_claimable!(nodes[0], payment_hash_4, payment_secret_4, 10000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_4);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);
}

#[test]
fn channel_monitor_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that ChannelMonitor is able to recover from various states.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4);

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);
	connect_blocks(&nodes[4], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[4].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);

	// Simple case with no pending HTLCs:
	let error_message = "Channel force-closed";
	nodes[1].node.force_close_broadcasting_latest_txn(&chan_1.2, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[0].node.get_our_node_id()], 100000);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, HTLCType::NONE);
		assert_eq!(node_txn.len(), 1);
		mine_transaction(&nodes[1], &node_txn[0]);
		if nodes[1].connect_style.borrow().updates_best_block_first() {
			let _ = nodes[1].tx_broadcaster.txn_broadcast();
		}

		mine_transaction(&nodes[0], &node_txn[0]);
		check_added_monitors!(nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_1, Some(node_txn[0].clone()), HTLCType::NONE);
	}
	check_closed_broadcast!(nodes[0], true);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	// One pending HTLC is discarded by the force-close:
	let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[1], &[&nodes[2], &nodes[3]], 3_000_000);

	// Simple case of one pending HTLC to HTLC-Timeout (note that the HTLC-Timeout is not
	// broadcasted until we reach the timelock time).
	let error_message = "Channel force-closed";
	nodes[1].node.force_close_broadcasting_latest_txn(&chan_2.2, &nodes[2].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::NONE);
		connect_blocks(&nodes[1], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + MIN_CLTV_EXPIRY_DELTA as u32 + 1);
		test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
		mine_transaction(&nodes[2], &node_txn[0]);
		check_added_monitors!(nodes[2], 1);
		test_txn_broadcast(&nodes[2], &chan_2, Some(node_txn[0].clone()), HTLCType::NONE);
	}
	check_closed_broadcast!(nodes[2], true);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
	assert_eq!(nodes[2].node.list_channels().len(), 1);
	check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[2].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	macro_rules! claim_funds {
		($node: expr, $prev_node: expr, $preimage: expr, $payment_hash: expr) => {
			{
				$node.node.claim_funds($preimage);
				expect_payment_claimed!($node, $payment_hash, 3_000_000);
				check_added_monitors!($node, 1);

				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, .. } } => {
						assert!(update_add_htlcs.is_empty());
						assert!(update_fail_htlcs.is_empty());
						assert_eq!(*node_id, $prev_node.node.get_our_node_id());
					},
					_ => panic!("Unexpected event"),
				};
			}
		}
	}

	// nodes[3] gets the preimage, but nodes[2] already disconnected, resulting in a nodes[2]
	// HTLC-Timeout and a nodes[3] claim against it (+ its own announces)
	let error_message = "Channel force-closed";
	nodes[2].node.force_close_broadcasting_latest_txn(&chan_3.2, &nodes[3].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_added_monitors!(nodes[2], 1);
	check_closed_broadcast!(nodes[2], true);
	let node2_commitment_txid;
	{
		let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::NONE);
		connect_blocks(&nodes[2], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + MIN_CLTV_EXPIRY_DELTA as u32 + 1);
		test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::TIMEOUT);
		node2_commitment_txid = node_txn[0].compute_txid();

		// Claim the payment on nodes[3], giving it knowledge of the preimage
		claim_funds!(nodes[3], nodes[2], payment_preimage_1, payment_hash_1);
		mine_transaction(&nodes[3], &node_txn[0]);
		check_added_monitors!(nodes[3], 1);
		check_preimage_claim(&nodes[3], &node_txn);
	}
	check_closed_broadcast!(nodes[3], true);
	assert_eq!(nodes[2].node.list_channels().len(), 0);
	assert_eq!(nodes[3].node.list_channels().len(), 1);
	check_closed_event!(nodes[2], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[3].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[3], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);

	// Drop the ChannelMonitor for the previous channel to avoid it broadcasting transactions and
	// confusing us in the following tests.
	let chan_3_mon = nodes[3].chain_monitor.chain_monitor.remove_monitor(&OutPoint { txid: chan_3.3.compute_txid(), index: 0 });

	// One pending HTLC to time out:
	let (payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[3], &[&nodes[4]], 3_000_000);
	// CLTV expires at TEST_FINAL_CLTV + 1 (current height) + 1 (added in send_payment for
	// buffer space).

	let (close_chan_update_1, close_chan_update_2) = {
		connect_blocks(&nodes[3], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
		let events = nodes[3].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		let close_chan_update_1 = match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, node_id } => {
				assert_eq!(node_id, nodes[4].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		check_added_monitors!(nodes[3], 1);

		// Clear bumped claiming txn spending node 2 commitment tx. Bumped txn are generated after reaching some height timer.
		{
			let mut node_txn = nodes[3].tx_broadcaster.txn_broadcasted.lock().unwrap();
			node_txn.retain(|tx| {
				if tx.input[0].previous_output.txid == node2_commitment_txid {
					false
				} else { true }
			});
		}

		let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, HTLCType::TIMEOUT);

		// Claim the payment on nodes[4], giving it knowledge of the preimage
		claim_funds!(nodes[4], nodes[3], payment_preimage_2, payment_hash_2);

		connect_blocks(&nodes[4], TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + 2);
		let events = nodes[4].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		let close_chan_update_2 = match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, node_id } => {
				assert_eq!(node_id, nodes[3].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		check_added_monitors!(nodes[4], 1);
		test_txn_broadcast(&nodes[4], &chan_4, None, HTLCType::SUCCESS);
		check_closed_event!(nodes[4], 1, ClosureReason::HTLCsTimedOut, [nodes[3].node.get_our_node_id()], 100000);

		mine_transaction(&nodes[4], &node_txn[0]);
		check_preimage_claim(&nodes[4], &node_txn);
		(close_chan_update_1, close_chan_update_2)
	};
	let node_id_4 = nodes[4].node.get_our_node_id();
	let node_id_3 = nodes[3].node.get_our_node_id();
	nodes[3].gossip_sync.handle_channel_update(Some(&node_id_4), &close_chan_update_2).unwrap();
	nodes[4].gossip_sync.handle_channel_update(Some(&node_id_3), &close_chan_update_1).unwrap();
	assert_eq!(nodes[3].node.list_channels().len(), 0);
	assert_eq!(nodes[4].node.list_channels().len(), 0);

	assert_eq!(nodes[3].chain_monitor.chain_monitor.watch_channel(OutPoint { txid: chan_3.3.compute_txid(), index: 0 }, chan_3_mon),
		Ok(ChannelMonitorUpdateStatus::Completed));
	check_closed_event!(nodes[3], 1, ClosureReason::HTLCsTimedOut, [node_id_4], 100000);
}

#[test]
fn test_justice_tx_htlc_timeout() {
	// Test justice txn built on revoked HTLC-Timeout tx, against both sides
	let mut alice_config = test_default_channel_config();
	alice_config.channel_handshake_config.announce_for_forwarding = true;
	alice_config.channel_handshake_limits.force_announced_channel_preference = false;
	alice_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = test_default_channel_config();
	bob_config.channel_handshake_config.announce_for_forwarding = true;
	bob_config.channel_handshake_limits.force_announced_channel_preference = false;
	bob_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 3;
	let user_cfgs = [Some(alice_config), Some(bob_config)];
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	// Create some new channels:
	let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// A pending HTLC which will be revoked:
	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from nodes[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_5.2);
	assert_eq!(revoked_local_txn.len(), 2); // First commitment tx, then HTLC tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_5.3.compute_txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to 0 are present
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].compute_txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);

	{
		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		{
			let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 1); // ChannelMonitor: penalty tx
			assert_eq!(node_txn[0].input.len(), 2); // We should claim the revoked output and the HTLC output
			check_spends!(node_txn[0], revoked_local_txn[0]);
			node_txn.swap_remove(0);
		}
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		test_txn_broadcast(&nodes[1], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::NONE);

		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
		// Verify broadcast of revoked HTLC-timeout
		let node_txn = test_txn_broadcast(&nodes[0], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::TIMEOUT);
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		// Broadcast revoked HTLC-timeout on node 1
		mine_transaction(&nodes[1], &node_txn[1]);
		test_revoked_htlc_claim_txn_broadcast(&nodes[1], node_txn[1].clone(), revoked_local_txn[0].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn test_justice_tx_htlc_success() {
	// Test justice txn built on revoked HTLC-Success tx, against both sides
	let mut alice_config = test_default_channel_config();
	alice_config.channel_handshake_config.announce_for_forwarding = true;
	alice_config.channel_handshake_limits.force_announced_channel_preference = false;
	alice_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = test_default_channel_config();
	bob_config.channel_handshake_config.announce_for_forwarding = true;
	bob_config.channel_handshake_limits.force_announced_channel_preference = false;
	bob_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 3;
	let user_cfgs = [Some(alice_config), Some(bob_config)];
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	// Create some new channels:
	let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// A pending HTLC which will be revoked:
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from B
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_6.2);
	assert_eq!(revoked_local_txn.len(), 1); // Only commitment tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_6.3.compute_txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to A are present
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_4);
	{
		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		{
			let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 1); // ChannelMonitor: penalty tx
			assert_eq!(node_txn[0].input.len(), 1); // We claim the received HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0]);
			node_txn.swap_remove(0);
		}
		check_added_monitors!(nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::NONE);

		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		let node_txn = test_txn_broadcast(&nodes[1], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::SUCCESS);
		check_added_monitors!(nodes[1], 1);
		mine_transaction(&nodes[0], &node_txn[1]);
		check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		test_revoked_htlc_claim_txn_broadcast(&nodes[0], node_txn[1].clone(), revoked_local_txn[0].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn revoked_output_claim() {
	// Simple test to ensure a node will claim a revoked output when a stale remote commitment
	// transaction is broadcast by its counterparty
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 1);
	// Only output is the full channel value back to nodes[0]:
	assert_eq!(revoked_local_txn[0].output.len(), 1);
	// Send a payment through, updating everyone's latest commitment txn
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 5000000);

	// Inform nodes[1] that nodes[0] broadcast a stale tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1); // ChannelMonitor: justice tx against revoked to_local output

	check_spends!(node_txn[0], revoked_local_txn[0]);

	// Inform nodes[0] that a watchtower cheated on its behalf, so it will force-close the chan
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	get_announce_close_broadcast_events(&nodes, 0, 1);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_forming_justice_tx_from_monitor_updates() {
	do_test_forming_justice_tx_from_monitor_updates(true);
	do_test_forming_justice_tx_from_monitor_updates(false);
}

fn do_test_forming_justice_tx_from_monitor_updates(broadcast_initial_commitment: bool) {
	// Simple test to make sure that the justice tx formed in WatchtowerPersister
	// is properly formed and can be broadcasted/confirmed successfully in the event
	// that a revoked commitment transaction is broadcasted
	// (Similar to `revoked_output_claim` test but we get the justice tx + broadcast manually)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let destination_script0 = chanmon_cfgs[0].keys_manager.get_destination_script([0; 32]).unwrap();
	let destination_script1 = chanmon_cfgs[1].keys_manager.get_destination_script([0; 32]).unwrap();
	let persisters = vec![WatchtowerPersister::new(destination_script0),
		WatchtowerPersister::new(destination_script1)];
	let node_cfgs = create_node_cfgs_with_persisters(2, &chanmon_cfgs, persisters.iter().collect());
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let funding_txo = OutPoint { txid: funding_tx.compute_txid(), index: 0 };

	if !broadcast_initial_commitment {
		// Send a payment to move the channel forward
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 5_000_000);
	}

	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output.
	// We'll keep this commitment transaction to broadcast once it's revoked.
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], channel_id);
	assert_eq!(revoked_local_txn.len(), 1);
	let revoked_commitment_tx = &revoked_local_txn[0];

	// Send another payment, now revoking the previous commitment tx
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 5_000_000);

	let justice_tx = persisters[1].justice_tx(funding_txo, &revoked_commitment_tx.compute_txid()).unwrap();
	check_spends!(justice_tx, revoked_commitment_tx);

	mine_transactions(&nodes[1], &[revoked_commitment_tx, &justice_tx]);
	mine_transactions(&nodes[0], &[revoked_commitment_tx, &justice_tx]);

	check_added_monitors!(nodes[1], 1);
	check_closed_event(&nodes[1], 1, ClosureReason::CommitmentTxConfirmed, false,
		&[nodes[0].node.get_our_node_id()], 100_000);
	get_announce_close_broadcast_events(&nodes, 1, 0);

	check_added_monitors!(nodes[0], 1);
	check_closed_event(&nodes[0], 1, ClosureReason::CommitmentTxConfirmed, false,
		&[nodes[1].node.get_our_node_id()], 100_000);

	// Check that the justice tx has sent the revoked output value to nodes[1]
	let monitor = get_monitor!(nodes[1], channel_id);
	let total_claimable_balance = monitor.get_claimable_balances().iter().fold(0, |sum, balance| {
		match balance {
			channelmonitor::Balance::ClaimableAwaitingConfirmations { amount_satoshis, .. } => sum + amount_satoshis,
			_ => panic!("Unexpected balance type"),
		}
	});
	// On the first commitment, node[1]'s balance was below dust so it didn't have an output
	let node1_channel_balance = if broadcast_initial_commitment { 0 } else { revoked_commitment_tx.output[0].value.to_sat() };
	let expected_claimable_balance = node1_channel_balance + justice_tx.output[0].value.to_sat();
	assert_eq!(total_claimable_balance, expected_claimable_balance);
}


#[test]
fn claim_htlc_outputs_shared_tx() {
	// Node revoked old state, htlcs haven't time out yet, claim them in shared justice tx
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some new channel:
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx
	let payment_preimage_1 = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
	let (_payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 2); // commitment tx + 1 HTLC-Timeout tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].compute_txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	check_spends!(revoked_local_txn[1], revoked_local_txn[0]);

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

	{
		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(node_txn.len(), 1); // ChannelMonitor: penalty tx

		assert_eq!(node_txn[0].input.len(), 3); // Claim the revoked output + both revoked HTLC outputs
		check_spends!(node_txn[0], revoked_local_txn[0]);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[1].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[2].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		// Finally, mine the penalty transaction and check that we get an HTLC failure after
		// ANTI_REORG_DELAY confirmations.
		mine_transaction(&nodes[1], &node_txn[0]);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[1], payment_hash_2, false);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn claim_htlc_outputs_single_tx() {
	// Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
	// time as two different claim transactions as we're gonna to timeout htlc with given a high current height
	let payment_preimage_1 = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
	let (_payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

	{
		confirm_transaction_at(&nodes[0], &revoked_local_txn[0], 100);
		check_added_monitors!(nodes[0], 1);
		confirm_transaction_at(&nodes[1], &revoked_local_txn[0], 100);
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		let mut events = nodes[0].node.get_and_clear_pending_events();
		expect_pending_htlcs_forwardable_conditions(events[0..2].to_vec(), &[HTLCDestination::FailedPayment { payment_hash: payment_hash_2 }]);
		match events.last().unwrap() {
			Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
			_ => panic!("Unexpected event"),
		}

		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcast();

		// Check the pair local commitment and HTLC-timeout broadcast due to HTLC expiration
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[0], chan_1.3);
		assert_eq!(node_txn[1].input.len(), 1);
		let witness_script = node_txn[1].input[0].witness.last().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		check_spends!(node_txn[1], node_txn[0]);

		// Filter out any non justice transactions.
		node_txn.retain(|tx| tx.input[0].previous_output.txid == revoked_local_txn[0].compute_txid());
		assert!(node_txn.len() > 3);

		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);

		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		check_spends!(node_txn[2], revoked_local_txn[0]);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[1].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[2].input[0].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		// Finally, mine the penalty transactions and check that we get an HTLC failure after
		// ANTI_REORG_DELAY confirmations.
		mine_transaction(&nodes[1], &node_txn[0]);
		mine_transaction(&nodes[1], &node_txn[1]);
		mine_transaction(&nodes[1], &node_txn[2]);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[1], payment_hash_2, false);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn test_htlc_on_chain_success() {
	// Test that in case of a unilateral close onchain, we detect the state of output and pass
	// the preimage backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// We test with two HTLCs simultaneously as that was not handled correctly in the past.
	// A --------------------> B ----------------------> C (preimage)
	// First, C should claim the HTLC outputs via HTLC-Success when its own latest local
	// commitment transaction was broadcast.
	// Then, B should learn the preimage from said transactions, attempting to claim backwards
	// towards B.
	// B should be able to claim via preimage if A then broadcasts its local tx.
	// Finally, when A sees B's latest local commitment transaction it should be able to claim
	// the HTLC outputs via the preimage it learned (which, once confirmed should generate a
	// PaymentSent event).

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Ensure all nodes are at the same height
	let node_max_height = nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (our_payment_preimage, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let (our_payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Broadcast legit commitment tx from C on B's chain
	// Broadcast HTLC Success transaction by C on received output from C's commitment tx on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_tx.len(), 1);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(our_payment_preimage);
	expect_payment_claimed!(nodes[2], payment_hash_1, 3_000_000);
	nodes[2].node.claim_funds(our_payment_preimage_2);
	expect_payment_claimed!(nodes[2], payment_hash_2, 3_000_000);
	check_added_monitors!(nodes[2], 2);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);

	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors!(nodes[2], 1);
	check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: 2 (2 * HTLC-Success tx)
	assert_eq!(node_txn.len(), 2);
	check_spends!(node_txn[0], commitment_tx[0]);
	check_spends!(node_txn[1], commitment_tx[0]);
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(node_txn[0].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert!(node_txn[1].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert_eq!(node_txn[0].lock_time, LockTime::ZERO);
	assert_eq!(node_txn[1].lock_time, LockTime::ZERO);

	// Verify that B's ChannelManager is able to extract preimage from HTLC Success tx and pass it backward
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![commitment_tx[0].clone(), node_txn[0].clone(), node_txn[1].clone()]));
	connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0.txid, chan_2.3.compute_txid());
		added_monitors.clear();
	}
	let forwarded_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(forwarded_events.len(), 3);
	match forwarded_events[0] {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
		_ => panic!("Unexpected event"),
	}
	let chan_id = Some(chan_1.2);
	match forwarded_events[1] {
		Event::PaymentForwarded { total_fee_earned_msat, prev_channel_id, claim_from_onchain_tx,
			next_channel_id, outbound_amount_forwarded_msat, ..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, chan_id);
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!()
	}
	match forwarded_events[2] {
		Event::PaymentForwarded { total_fee_earned_msat, prev_channel_id, claim_from_onchain_tx,
			next_channel_id, outbound_amount_forwarded_msat, ..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, chan_id);
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!()
	}
	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 2);
		assert_eq!(added_monitors[0].0.txid, chan_1.3.compute_txid());
		assert_eq!(added_monitors[1].0.txid, chan_1.3.compute_txid());
		added_monitors.clear();
	}
	assert_eq!(events.len(), 3);

	let nodes_2_event = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	let nodes_0_event = remove_first_msg_event_to_node(&nodes[0].node.get_our_node_id(), &mut events);

	match nodes_2_event {
		MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, node_id: _ } => {},
		_ => panic!("Unexpected event"),
	}

	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	macro_rules! check_tx_local_broadcast {
		($node: expr, $htlc_offered: expr, $commitment_tx: expr) => { {
			let mut node_txn = $node.tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 2);
			// Node[1]: 2 * HTLC-timeout tx
			// Node[0]: 2 * HTLC-timeout tx
			check_spends!(node_txn[0], $commitment_tx);
			check_spends!(node_txn[1], $commitment_tx);
			assert_ne!(node_txn[0].lock_time, LockTime::ZERO);
			assert_ne!(node_txn[1].lock_time, LockTime::ZERO);
			if $htlc_offered {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_p2wsh()); // revokeable output
				assert!(node_txn[1].output[0].script_pubkey.is_p2wsh()); // revokeable output
			} else {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_p2wpkh()); // direct payment
				assert!(node_txn[1].output[0].script_pubkey.is_p2wpkh()); // direct payment
			}
			node_txn.clear();
		} }
	}
	// nodes[1] now broadcasts its own timeout-claim of the output that nodes[2] just claimed via success.
	check_tx_local_broadcast!(nodes[1], false, commitment_tx[0]);

	// Broadcast legit commitment tx from A on B's chain
	// Broadcast preimage tx by B on offered output from A commitment tx  on A's chain
	let node_a_commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	check_spends!(node_a_commitment_tx[0], chan_1.3);
	mine_transaction(&nodes[1], &node_a_commitment_tx[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert!(node_txn.len() == 1 || node_txn.len() == 3); // HTLC-Success, 2* RBF bumps of above HTLC txn
	let commitment_spend =
		if node_txn.len() == 1 {
			&node_txn[0]
		} else {
			// Certain `ConnectStyle`s will cause RBF bumps of the previous HTLC transaction to be broadcast.
			// FullBlockViaListen
			if node_txn[0].input[0].previous_output.txid == node_a_commitment_tx[0].compute_txid() {
				check_spends!(node_txn[1], commitment_tx[0]);
				check_spends!(node_txn[2], commitment_tx[0]);
				assert_ne!(node_txn[1].input[0].previous_output.vout, node_txn[2].input[0].previous_output.vout);
				&node_txn[0]
			} else {
				check_spends!(node_txn[0], commitment_tx[0]);
				check_spends!(node_txn[1], commitment_tx[0]);
				assert_ne!(node_txn[0].input[0].previous_output.vout, node_txn[1].input[0].previous_output.vout);
				&node_txn[2]
			}
		};

	check_spends!(commitment_spend, node_a_commitment_tx[0]);
	assert_eq!(commitment_spend.input.len(), 2);
	assert_eq!(commitment_spend.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(commitment_spend.input[1].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(commitment_spend.lock_time.to_consensus_u32(), nodes[1].best_block_info().1);
	assert!(commitment_spend.output[0].script_pubkey.is_p2wpkh()); // direct payment
	// We don't bother to check that B can claim the HTLC output on its commitment tx here as
	// we already checked the same situation with A.

	// Verify that A's ChannelManager is able to extract preimage from preimage tx and generate PaymentSent
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, vec![node_a_commitment_tx[0].clone(), commitment_spend.clone()]));
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + MIN_CLTV_EXPIRY_DELTA as u32); // Confirm blocks until the HTLC expires
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 5);
	let mut first_claimed = false;
	for event in events {
		match event {
			Event::PaymentSent { payment_preimage, payment_hash, .. } => {
				if payment_preimage == our_payment_preimage && payment_hash == payment_hash_1 {
					assert!(!first_claimed);
					first_claimed = true;
				} else {
					assert_eq!(payment_preimage, our_payment_preimage_2);
					assert_eq!(payment_hash, payment_hash_2);
				}
			},
			Event::PaymentPathSuccessful { .. } => {},
			Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
	check_tx_local_broadcast!(nodes[0], true, node_a_commitment_tx[0]);
}

fn do_test_htlc_on_chain_timeout(connect_style: ConnectStyle) {
	// Test that in case of a unilateral close onchain, we detect the state of output and
	// timeout the HTLC backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A ------------------> B ----------------------> C (timeout)
	//    B's commitment tx 		C's commitment tx
	//    	      \                                  \
	//    	   B's HTLC timeout tx		     B's timeout tx

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = connect_style;
	*nodes[1].connect_style.borrow_mut() = connect_style;
	*nodes[2].connect_style.borrow_mut() = connect_style;

	// Create some intial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance the network a bit by relaying one payment thorugh all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (_payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);

	// Broadcast legit commitment tx from C on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	check_added_monitors!(nodes[2], 0);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash.clone() }]);
	check_added_monitors!(nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[1].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors!(nodes[2], 1);
	check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 0);

	// Broadcast timeout transaction by B on received output from C's commitment tx on B's chain
	// Verify that B's ChannelManager is able to detect that HTLC is timeout by its own tx and react backward in consequence
	mine_transaction(&nodes[1], &commitment_tx[0]);
	check_closed_event!(&nodes[1], 1, ClosureReason::CommitmentTxConfirmed, false
		, [nodes[2].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], 200 - nodes[2].best_block_info().1);
	let timeout_tx = {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		if nodes[1].connect_style.borrow().skips_blocks() {
			assert_eq!(txn.len(), 1);
		} else {
			assert_eq!(txn.len(), 3); // Two extra fee bumps for timeout transaction
		}
		txn.iter().for_each(|tx| check_spends!(tx, commitment_tx[0]));
		assert_eq!(txn[0].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		txn.remove(0)
	};

	mine_transaction(&nodes[1], &timeout_tx);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Broadcast legit commitment tx from B on A's chain
	let commitment_tx = get_local_commitment_txn!(nodes[1], chan_1.2);
	check_spends!(commitment_tx[0], chan_1.3);

	mine_transaction(&nodes[0], &commitment_tx[0]);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + MIN_CLTV_EXPIRY_DELTA as u32); // Confirm blocks until the HTLC expires

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // 1 timeout tx
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
}

#[test]
fn test_htlc_on_chain_timeout() {
	do_test_htlc_on_chain_timeout(ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_htlc_on_chain_timeout(ConnectStyle::TransactionsFirstSkippingBlocks);
	do_test_htlc_on_chain_timeout(ConnectStyle::FullBlockViaListen);
}

#[test]
fn test_simple_commitment_revoked_fail_backward() {
	// Test that in case of a revoked commitment tx, we detect the resolution of output by justice tx
	// and fail backward accordingly.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, _payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let (_, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);
			expect_payment_failed_with_update!(nodes[0], payment_hash, false, chan_2.0.contents.short_channel_id, true);
		},
		_ => panic!("Unexpected event"),
	}
}

fn do_test_commitment_revoked_fail_backward_exhaustive(deliver_bs_raa: bool, use_dust: bool, no_to_remote: bool) {
	// Test that if our counterparty broadcasts a revoked commitment transaction we fail all
	// pending HTLCs on that channel backwards even if the HTLCs aren't present in our latest
	// commitment transaction anymore.
	// To do this, we have the peer which will broadcast a revoked commitment transaction send
	// a number of update_fail/commitment_signed updates without ever sending the RAA in
	// response to our commitment_signed. This is somewhat misbehavior-y, though not
	// technically disallowed and we should probably handle it reasonably.
	// Note that this is pretty exhaustive as an outbound HTLC which we haven't yet
	// failed/fulfilled backwards must be in at least one of the latest two remote commitment
	// transactions:
	// * Once we move it out of our holding cell/add it, we will immediately include it in a
	//   commitment_signed (implying it will be in the latest remote commitment transaction).
	// * Once they remove it, we will send a (the first) commitment_signed without the HTLC,
	//   and once they revoke the previous commitment transaction (allowing us to send a new
	//   commitment_signed) we will be free to fail/fulfill the HTLC backwards.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, _payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], if no_to_remote { 10_000 } else { 3_000_000 });
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(revoked_local_txn[0].output.len(), if no_to_remote { 1 } else { 2 });
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let value = if use_dust {
		// The dust limit applied to HTLC outputs considers the fee of the HTLC transaction as
		// well, so HTLCs at exactly the dust limit will not be included in commitment txn.
		nodes[2].node.per_peer_state.read().unwrap().get(&nodes[1].node.get_our_node_id())
			.unwrap().lock().unwrap().channel_by_id.get(&chan_2.2).unwrap().context().holder_dust_limit_satoshis * 1000
	} else { 3000000 };

	let (_, first_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, second_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, third_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);

	nodes[2].node.fail_htlc_backwards(&first_payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::FailedPayment { payment_hash: first_payment_hash }]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	// Drop the last RAA from 3 -> 2

	nodes[2].node.fail_htlc_backwards(&second_payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::FailedPayment { payment_hash: second_payment_hash }]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);

	nodes[2].node.fail_htlc_backwards(&third_payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::FailedPayment { payment_hash: third_payment_hash }]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	// At this point first_payment_hash has dropped out of the latest two commitment
	// transactions that nodes[1] is tracking...
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is (still) in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);

	// Add a fourth HTLC, this one will get sequestered away in nodes[1]'s holding cell waiting
	// on nodes[2]'s RAA.
	let (route, fourth_payment_hash, _, fourth_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[2], 1000000);
	nodes[1].node.send_payment_with_route(route, fourth_payment_hash,
		RecipientOnionFields::secret_only(fourth_payment_secret), PaymentId(fourth_payment_hash.0)).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 0);

	if deliver_bs_raa {
		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_raa);
		// One monitor for the new revocation preimage, no second on as we won't generate a new
		// commitment transaction for nodes[0] until process_pending_htlc_forwards().
		check_added_monitors!(nodes[1], 1);
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::HTLCHandlingFailed { .. } => { },
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		// Deliberately don't process the pending fail-back so they all fail back at once after
		// block connection just like the !deliver_bs_raa case
	}

	let mut failed_htlcs = new_hash_set();
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_added_monitors!(nodes[1], 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), if deliver_bs_raa { 3 + nodes.len() - 1 } else { 4 + nodes.len() });
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. }
	)));
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::PaymentPathFailed { ref payment_hash, .. } if *payment_hash == fourth_payment_hash
	)));
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::PaymentFailed { ref payment_hash, .. } if *payment_hash == Some(fourth_payment_hash)
	)));

	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), if deliver_bs_raa { 4 } else { 3 });

	if deliver_bs_raa {
		let nodes_2_event = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
		match nodes_2_event {
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
				assert_eq!(nodes[2].node.get_our_node_id(), *node_id);
				assert_eq!(update_add_htlcs.len(), 1);
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
			},
			_ => panic!("Unexpected event"),
		}
	}

	let nodes_2_event = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	match nodes_2_event {
		MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { msg: Some(msgs::ErrorMessage { channel_id, ref data }) }, node_id: _ } => {
			assert_eq!(channel_id, chan_2.2);
			assert_eq!(data.as_str(), "Channel closed because commitment or closing transaction was confirmed on chain.");
		},
		_ => panic!("Unexpected event"),
	}

	let nodes_0_event = remove_first_msg_event_to_node(&nodes[0].node.get_our_node_id(), &mut events);
	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 3);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[1]);
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[2]);

			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 6);
			match events[0] {
				Event::PaymentPathFailed { ref payment_hash, ref failure, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
					// If we delivered B's RAA we got an unknown preimage error, not something
					// that we should update our routing table for.
					if !deliver_bs_raa {
						if let PathFailure::OnPath { network_update: Some(_) } = failure { } else { panic!("Unexpected path failure") }
					}
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(first_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
			match events[2] {
				Event::PaymentPathFailed { ref payment_hash, failure: PathFailure::OnPath { network_update: Some(_) }, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[3] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(second_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
			match events[4] {
				Event::PaymentPathFailed { ref payment_hash, failure: PathFailure::OnPath { network_update: Some(_) }, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[5] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(third_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { .. } } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(failed_htlcs.contains(&first_payment_hash.0));
	assert!(failed_htlcs.contains(&second_payment_hash.0));
	assert!(failed_htlcs.contains(&third_payment_hash.0));
}

#[test]
fn test_commitment_revoked_fail_backward_exhaustive_a() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, false);
}

#[test]
fn test_commitment_revoked_fail_backward_exhaustive_b() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, true);
}

#[test]
fn fail_backward_pending_htlc_upon_channel_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);

	// Alice -> Bob: Route a payment but without Bob sending revoke_and_ack.
	{
		let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 50_000);
		nodes[0].node.send_payment_with_route(route, payment_hash, RecipientOnionFields::secret_only(payment_secret),
			PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let payment_event = {
			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);
	}

	// Alice -> Bob: Route another payment but now Alice waits for Bob's earlier revoke_and_ack.
	let (route, failed_payment_hash, _, failed_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 50_000);
	{
		nodes[0].node.send_payment_with_route(route, failed_payment_hash,
			RecipientOnionFields::secret_only(failed_payment_secret), PaymentId(failed_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 0);

		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Alice <- Bob: Send a malformed update_add_htlc so Alice fails the channel.
	{
		let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 50_000);

		let secp_ctx = Secp256k1::new();
		let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
		let current_height = nodes[1].node.best_block.read().unwrap().height + 1;
		let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
		let (onion_payloads, _amount_msat, cltv_expiry) = onion_utils::build_onion_payloads(
			&route.paths[0], 50_000, &recipient_onion_fields, current_height, &None).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
		let onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();

		// Send a 0-msat update_add_htlc to fail the channel.
		let update_add_htlc = msgs::UpdateAddHTLC {
			channel_id: chan.2,
			htlc_id: 0,
			amount_msat: 0,
			payment_hash,
			cltv_expiry,
			onion_routing_packet,
			skimmed_fee_msat: None,
			blinding_point: None,
		};
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add_htlc);
	}
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3);
	// Check that Alice fails backward the pending HTLC from the second payment.
	match events[0] {
		Event::PaymentPathFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, failed_payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, Some(failed_payment_hash));
		},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		Event::ChannelClosed { reason: ClosureReason::ProcessingError { ref err }, .. } => {
			assert_eq!(err, "Remote side tried to send a 0-msat HTLC");
		},
		_ => panic!("Unexpected event {:?}", events[1]),
	}
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_htlc_ignore_latest_remote_commitment() {
	// Test that HTLC transactions spending the latest remote commitment transaction are simply
	// ignored if we cannot claim them. This originally tickled an invalid unwrap().
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	if *nodes[1].connect_style.borrow() == ConnectStyle::FullBlockViaListen {
		// We rely on the ability to connect a block redundantly, which isn't allowed via
		// `chain::Listen`, so we never run the test if we randomly get assigned that
		// connect_style.
		return;
	}
	let funding_tx = create_announced_chan_between_nodes(&nodes, 0, 1).3;
	let error_message = "Channel force-closed";
	route_payment(&nodes[0], &[&nodes[1]], 10000000);
	nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[1].node.get_our_node_id()], 100000);

	let node_txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
	assert_eq!(node_txn.len(), 2);
	check_spends!(node_txn[0], funding_tx);
	check_spends!(node_txn[1], node_txn[0]);

	let block = create_dummy_block(nodes[1].best_block_hash(), 42, vec![node_txn[0].clone()]);
	connect_block(&nodes[1], &block);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);

	// Duplicate the connect_block call since this may happen due to other listeners
	// registering new transactions
	connect_block(&nodes[1], &block);
}

#[test]
fn test_force_close_fail_back() {
	// Check which HTLCs are failed-backwards on channel force-closure
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);

	let mut payment_event = {
		nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	check_added_monitors!(nodes[1], 1);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);
	let (_, _) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	// nodes[2] now has the latest commitment transaction, but hasn't revoked its previous
	// state or updated nodes[1]' state. Now force-close and broadcast that commitment/HTLC
	// transaction and ensure nodes[1] doesn't fail-backwards (this was originally a bug!).
	let error_message = "Channel force-closed";
	nodes[2].node.force_close_broadcasting_latest_txn(&payment_event.commitment_msg.channel_id, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors!(nodes[2], 1);
	check_closed_event!(nodes[2], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[1].node.get_our_node_id()], 100000);
	let commitment_tx = {
		let mut node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// Note that we don't bother broadcasting the HTLC-Success transaction here as we don't
		// have a use for it unless nodes[2] learns the preimage somehow, the funds will go
		// back to nodes[1] upon timeout otherwise.
		assert_eq!(node_txn.len(), 1);
		node_txn.remove(0)
	};

	mine_transaction(&nodes[1], &commitment_tx);

	// Note no UpdateHTLCs event here from nodes[1] to nodes[0]!
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);

	// Now check that if we add the preimage to ChannelMonitor it broadcasts our HTLC-Success..
	{
		get_monitor!(nodes[2], payment_event.commitment_msg.channel_id)
			.provide_payment_preimage(&our_payment_hash, &our_payment_preimage, &node_cfgs[2].tx_broadcaster, &LowerBoundedFeeEstimator::new(node_cfgs[2].fee_estimator), &node_cfgs[2].logger);
	}
	mine_transaction(&nodes[2], &commitment_tx);
	let mut node_txn = nodes[2].tx_broadcaster.txn_broadcast();
	assert_eq!(node_txn.len(), if nodes[2].connect_style.borrow().updates_best_block_first() { 2 } else { 1 });
	let htlc_tx = node_txn.pop().unwrap();
	assert_eq!(htlc_tx.input.len(), 1);
	assert_eq!(htlc_tx.input[0].previous_output.txid, commitment_tx.compute_txid());
	assert_eq!(htlc_tx.lock_time, LockTime::ZERO); // Must be an HTLC-Success
	assert_eq!(htlc_tx.input[0].witness.len(), 5); // Must be an HTLC-Success

	check_spends!(htlc_tx, commitment_tx);
}

#[test]
fn test_dup_events_on_peer_disconnect() {
	// Test that if we receive a duplicative update_fulfill_htlc message after a reconnect we do
	// not generate a corresponding duplicative PaymentSent event. This did not use to be the case
	// as we used to generate the event immediately upon receipt of the payment preimage in the
	// update_fulfill_htlc message.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 1_000_000);
	check_added_monitors!(nodes[1], 1);
	let claim_msgs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &claim_msgs.update_fulfill_htlcs[0]);
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_path_successful!(nodes[0]);
}

#[test]
fn test_peer_disconnected_before_funding_broadcasted() {
	// Test that channels are closed with `ClosureReason::DisconnectedPeer` if the peer disconnects
	// before the funding transaction has been broadcasted, and doesn't reconnect back within time.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Open a channel between `nodes[0]` and `nodes[1]`, for which the funding transaction is never
	// broadcasted, even though it's created by `nodes[0]`.
	let expected_temporary_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 500_000_000, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	let (temporary_channel_id, tx, _funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);
	assert_eq!(temporary_channel_id, expected_temporary_channel_id);

	assert!(nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).is_ok());

	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	assert_eq!(funding_created_msg.temporary_channel_id, expected_temporary_channel_id);

	// Even though the funding transaction is created by `nodes[0]`, the `FundingCreated` msg is
	// never sent to `nodes[1]`, and therefore the tx is never signed by either party nor
	// broadcasted.
	{
		assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);
	}

	// The peers disconnect before the funding is broadcasted.
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	// The time for peers to reconnect expires.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	// Ensure that the channel is closed with `ClosureReason::DisconnectedPeer` and a
	// `DiscardFunding` event when the peers are disconnected and do not reconnect before the
	// funding transaction is broadcasted.
	check_closed_event!(&nodes[0], 2, ClosureReason::DisconnectedPeer, true
		, [nodes[1].node.get_our_node_id()], 1000000);
	check_closed_event!(&nodes[1], 1, ClosureReason::DisconnectedPeer, false
		, [nodes[0].node.get_our_node_id()], 1000000);
}

#[test]
fn test_simple_peer_disconnect() {
	// Test that we can reconnect when there are no lost messages
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_nodes(reconnect_args);

	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_2 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_2);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_1);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	let (payment_preimage_3, payment_hash_3, ..) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000);
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	let payment_hash_6 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage_3)
			.skip_last(true)
	);
	fail_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], true, payment_hash_5);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_fails.0 = 1;
	reconnect_args.pending_cell_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	{
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 4);
		match events[0] {
			Event::PaymentSent { payment_preimage, payment_hash, .. } => {
				assert_eq!(payment_preimage, payment_preimage_3);
				assert_eq!(payment_hash, payment_hash_3);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentPathSuccessful { .. } => {},
			_ => panic!("Unexpected event"),
		}
		match events[2] {
			Event::PaymentPathFailed { payment_hash, payment_failed_permanently, .. } => {
				assert_eq!(payment_hash, payment_hash_5);
				assert!(payment_failed_permanently);
			},
			_ => panic!("Unexpected event"),
		}
		match events[3] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, Some(payment_hash_5));
			},
			_ => panic!("Unexpected event"),
		}
	}
	check_added_monitors(&nodes[0], 1);

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_4);
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_6);
}

fn do_test_drop_messages_peer_disconnect(messages_delivered: u8, simulate_broken_lnd: bool) {
	// Test that we can reconnect when in-flight HTLC updates get dropped
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let mut as_channel_ready = None;
	let channel_id = if messages_delivered == 0 {
		let (channel_ready, chan_id, _) = create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001);
		as_channel_ready = Some(channel_ready);
		// nodes[1] doesn't receive the channel_ready message (it'll be re-sent on reconnect)
		// Note that we store it so that if we're running with `simulate_broken_lnd` we can deliver
		// it before the channel_reestablish message.
		chan_id
	} else {
		create_announced_chan_between_nodes(&nodes, 0, 1).2
	};

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);

	let payment_event = {
		nodes[0].node.send_payment_with_route(route, payment_hash_1,
			RecipientOnionFields::secret_only(payment_secret_1), PaymentId(payment_hash_1.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(nodes[1].node.get_our_node_id(), payment_event.node_id);

	if messages_delivered < 2 {
		// Drop the payment_event messages, and let them get re-generated in reconnect_nodes!
	} else {
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		if messages_delivered >= 3 {
			nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
			check_added_monitors!(nodes[1], 1);
			let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

			if messages_delivered >= 4 {
				nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[0], 1);

				if messages_delivered >= 5 {
					nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed);
					let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[0], 1);

					if messages_delivered >= 6 {
						nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
						assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[1], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	if messages_delivered < 3 {
		if simulate_broken_lnd {
			// lnd has a long-standing bug where they send a channel_ready prior to a
			// channel_reestablish if you reconnect prior to channel_ready time.
			//
			// Here we simulate that behavior, delivering a channel_ready immediately on
			// reconnect. Note that we don't bother skipping the now-duplicate channel_ready sent
			// in `reconnect_nodes` but we currently don't fail based on that.
			//
			// See-also <https://github.com/lightningnetwork/lnd/issues/4006>
			nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_channel_ready.as_ref().unwrap().0);
		}
		// Even if the channel_ready messages get exchanged, as long as nothing further was
		// received on either side, both sides will need to resend them.
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_channel_ready = (true, true);
		reconnect_args.pending_htlc_adds.1 = 1;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 3 {
		// nodes[0] still wants its RAA + commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_responding_commitment_signed.0 = true;
		reconnect_args.pending_raa.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 4 {
		// nodes[0] still wants its commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_responding_commitment_signed.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 5 {
		// nodes[1] still wants its final RAA
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_raa.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 6 {
		// Everything was delivered...
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	let events_1 = nodes[1].node.get_and_clear_pending_events();
	if messages_delivered == 0 {
		assert_eq!(events_1.len(), 2);
		match events_1[0] {
			Event::ChannelReady { .. } => { },
			_ => panic!("Unexpected event"),
		};
		match events_1[1] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	} else {
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	nodes[1].node.process_pending_htlc_forwards();

	let events_2 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, amount_msat, receiver_node_id, via_channel_id, .. } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amount_msat, 1_000_000);
			assert_eq!(receiver_node_id.unwrap(), nodes[1].node.get_our_node_id());
			assert_eq!(via_channel_id, Some(channel_id));
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_1, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);

	let events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let (update_fulfill_htlc, commitment_signed) = match events_3[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if messages_delivered >= 1 {
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlc);

		let events_4 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
				assert_eq!(payment_preimage_1, *payment_preimage);
				assert_eq!(payment_hash_1, *payment_hash);
			},
			_ => panic!("Unexpected event"),
		}

		if messages_delivered >= 2 {
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
			check_added_monitors!(nodes[0], 1);
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

			if messages_delivered >= 3 {
				nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[1], 1);

				if messages_delivered >= 4 {
					nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed);
					let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[1], 1);

					if messages_delivered >= 5 {
						nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
						assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[0], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	if messages_delivered < 2 {
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_htlc_claims.0 = 1;
		reconnect_nodes(reconnect_args);
		if messages_delivered < 1 {
			expect_payment_sent!(nodes[0], payment_preimage_1);
		} else {
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		}
	} else if messages_delivered == 2 {
		// nodes[0] still wants its RAA + commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_responding_commitment_signed.1 = true;
		reconnect_args.pending_raa.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 3 {
		// nodes[0] still wants its commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_responding_commitment_signed.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 4 {
		// nodes[1] still wants its final RAA
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_raa.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 5 {
		// Everything was delivered...
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	if messages_delivered == 1 || messages_delivered == 2 {
		expect_payment_path_successful!(nodes[0]);
	}
	if messages_delivered <= 5 {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	}
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	if messages_delivered > 2 {
		expect_payment_path_successful!(nodes[0]);
	}

	// Channel should still work fine...
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let payment_preimage_2 = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_drop_messages_peer_disconnect_a() {
	do_test_drop_messages_peer_disconnect(0, true);
	do_test_drop_messages_peer_disconnect(0, false);
	do_test_drop_messages_peer_disconnect(1, false);
	do_test_drop_messages_peer_disconnect(2, false);
}

#[test]
fn test_drop_messages_peer_disconnect_b() {
	do_test_drop_messages_peer_disconnect(3, false);
	do_test_drop_messages_peer_disconnect(4, false);
	do_test_drop_messages_peer_disconnect(5, false);
	do_test_drop_messages_peer_disconnect(6, false);
}

#[test]
fn test_channel_ready_without_best_block_updated() {
	// Previously, if we were offline when a funding transaction was locked in, and then we came
	// back online, calling best_block_updated once followed by transactions_confirmed, we'd not
	// generate a channel_ready until a later best_block_updated. This tests that we generate the
	// channel_ready immediately instead.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = ConnectStyle::BestBlockFirstSkippingBlocks;

	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	let conf_height = nodes[0].best_block_info().1 + 1;
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);
	let block_txn = [funding_tx];
	let conf_txn: Vec<_> = block_txn.iter().enumerate().collect();
	let conf_block_header = nodes[0].get_block_header(conf_height);
	nodes[0].node.transactions_confirmed(&conf_block_header, &conf_txn[..], conf_height);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_channel_ready);
}

#[test]
fn test_channel_monitor_skipping_block_when_channel_manager_is_leading() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Let channel_manager get ahead of chain_monitor by 1 block.
	// This is to emulate race-condition where newly added channel_monitor skips processing 1 block,
	// in case where client calls block_connect on channel_manager first and then on chain_monitor.
	let height_1 = nodes[0].best_block_info().1 + 1;
	let mut block_1 = create_dummy_block(nodes[0].best_block_hash(), height_1, Vec::new());

	nodes[0].blocks.lock().unwrap().push((block_1.clone(), height_1));
	nodes[0].node.block_connected(&block_1, height_1);

	// Create channel, and it gets added to chain_monitor in funding_created.
	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	// Now, newly added channel_monitor in chain_monitor hasn't processed block_1,
	// but it's best_block is block_1, since that was populated by channel_manager, and channel_manager
	// was running ahead of chain_monitor at the time of funding_created.
	// Later on, subsequent blocks are connected to both channel_manager and chain_monitor.
	// Hence, this channel's channel_monitor skipped block_1, directly tries to process subsequent blocks.
	confirm_transaction_at(&nodes[0], &funding_tx, nodes[0].best_block_info().1 + 1);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_channel_ready);
}

#[test]
fn test_channel_monitor_skipping_block_when_channel_manager_is_lagging() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Let chain_monitor get ahead of channel_manager by 1 block.
	// This is to emulate race-condition where newly added channel_monitor skips processing 1 block,
	// in case where client calls block_connect on chain_monitor first and then on channel_manager.
	let height_1 = nodes[0].best_block_info().1 + 1;
	let mut block_1 = create_dummy_block(nodes[0].best_block_hash(), height_1, Vec::new());

	nodes[0].blocks.lock().unwrap().push((block_1.clone(), height_1));
	nodes[0].chain_monitor.chain_monitor.block_connected(&block_1, height_1);

	// Create channel, and it gets added to chain_monitor in funding_created.
	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	// channel_manager can't really skip block_1, it should get it eventually.
	nodes[0].node.block_connected(&block_1, height_1);

	// Now, newly added channel_monitor in chain_monitor hasn't processed block_1, it's best_block is
	// the block before block_1, since that was populated by channel_manager, and channel_manager was
	// running behind at the time of funding_created.
	// Later on, subsequent blocks are connected to both channel_manager and chain_monitor.
	// Hence, this channel's channel_monitor skipped block_1, directly tries to process subsequent blocks.
	confirm_transaction_at(&nodes[0], &funding_tx, nodes[0].best_block_info().1 + 1);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_channel_ready);
}

#[test]
fn test_drop_messages_peer_disconnect_dual_htlc() {
	// Test that we can handle reconnecting when both sides of a channel have pending
	// commitment_updates when we disconnect.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Now try to send a second payment which will fail to send
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, payment_hash_2,
		RecipientOnionFields::secret_only(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);
	check_added_monitors!(nodes[1], 1);

	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]);
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
					assert_eq!(*payment_hash, payment_hash_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
			let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	assert!(as_resp.0.is_none());
	assert!(bs_resp.0.is_none());

	assert!(bs_resp.1.is_none());
	assert!(bs_resp.2.is_none());

	assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);

	assert_eq!(as_resp.2.as_ref().unwrap().update_add_htlcs.len(), 1);
	assert!(as_resp.2.as_ref().unwrap().update_fulfill_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fee.is_none());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), as_resp.1.as_ref().unwrap());
	let bs_second_commitment_signed = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_second_commitment_signed.update_add_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
	let as_commitment_signed = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_commitment_signed.update_add_htlcs.is_empty());
	assert!(as_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(as_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_signed.commitment_signed);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed.commitment_signed);
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, .. } => {
			assert_eq!(payment_hash_2, *payment_hash);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	expect_payment_path_successful!(nodes[0]);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

fn do_test_htlc_timeout(send_partial_mpp: bool) {
	// If the user fails to claim/fail an HTLC within the HTLC CLTV timeout we fail it for them
	// to avoid our counterparty failing the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let our_payment_hash = if send_partial_mpp {
		let (route, our_payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100000);
		// Use the utility function send_payment_along_path to send the payment with MPP data which
		// indicates there are more HTLCs coming.
		let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
		let payment_id = PaymentId([42; 32]);
		let session_privs = nodes[0].node.test_add_new_pending_payment(our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), payment_id, &route).unwrap();
		nodes[0].node.test_send_payment_along_path(&route.paths[0], &our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id,
			&None, session_privs[0]).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		// Now do the relevant commitment_signed/RAA dances along the path, noting that the final
		// hop should *not* yet generate any PaymentClaimable event(s).
		pass_along_path(&nodes[0], &[&nodes[1]], 100000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);
		our_payment_hash
	} else {
		route_payment(&nodes[0], &[&nodes[1]], 100000).1
	};

	let mut block = create_dummy_block(nodes[0].best_block_hash(), 42, Vec::new());
	connect_block(&nodes[0], &block);
	connect_block(&nodes[1], &block);
	let block_count = TEST_FINAL_CLTV + CHAN_CONFIRM_DEPTH + 2 - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS;
	for _ in CHAN_CONFIRM_DEPTH + 2..block_count {
		block.header.prev_blockhash = block.block_hash();
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
	}

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);

	check_added_monitors!(nodes[1], 1);
	let htlc_timeout_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_timeout_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_timeout_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_timeout_updates.update_fail_malformed_htlcs.is_empty());
	assert!(htlc_timeout_updates.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_timeout_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_timeout_updates.commitment_signed, false);
	// 100_000 msat as u64, followed by the height at which we failed back above
	let mut expected_failure_data = (100_000 as u64).to_be_bytes().to_vec();
	expected_failure_data.extend_from_slice(&(block_count - 1).to_be_bytes());
	expect_payment_failed!(nodes[0], our_payment_hash, true, 0x4000 | 15, &expected_failure_data[..]);
}

#[test]
fn test_htlc_timeout() {
	do_test_htlc_timeout(true);
	do_test_htlc_timeout(false);
}

fn do_test_holding_cell_htlc_add_timeouts(forwarded_htlc: bool) {
	// Tests that HTLCs in the holding cell are timed out after the requisite number of blocks.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	// Route a first payment to get the 1 -> 2 channel in awaiting_raa...
	let (route, first_payment_hash, _, first_payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[2], 100000);
	nodes[1].node.send_payment_with_route(route, first_payment_hash,
		RecipientOnionFields::secret_only(first_payment_secret), PaymentId(first_payment_hash.0)).unwrap();
	assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);
	check_added_monitors!(nodes[1], 1);

	// Now attempt to route a second payment, which should be placed in the holding cell
	let sending_node = if forwarded_htlc { &nodes[0] } else { &nodes[1] };
	let (route, second_payment_hash, _, second_payment_secret) = get_route_and_payment_hash!(sending_node, nodes[2], 100000);
	sending_node.node.send_payment_with_route(route, second_payment_hash,
		RecipientOnionFields::secret_only(second_payment_secret), PaymentId(second_payment_hash.0)).unwrap();
	if forwarded_htlc {
		check_added_monitors!(nodes[0], 1);
		let payment_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
	}
	check_added_monitors!(nodes[1], 0);

	connect_blocks(&nodes[1], TEST_FINAL_CLTV - LATENCY_GRACE_PERIOD_BLOCKS);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	connect_blocks(&nodes[1], 1);

	if forwarded_htlc {
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
		check_added_monitors!(nodes[1], 1);
		let fail_commit = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(fail_commit.len(), 1);
		match fail_commit[0] {
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fail_htlcs, ref commitment_signed, .. }, .. } => {
				nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
				commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, true, true);
			},
			_ => unreachable!(),
		}
		expect_payment_failed_with_update!(nodes[0], second_payment_hash, false, chan_2.0.contents.short_channel_id, false);
	} else {
		expect_payment_failed!(nodes[1], second_payment_hash, false);
	}
}

#[test]
fn test_holding_cell_htlc_add_timeouts() {
	do_test_holding_cell_htlc_add_timeouts(false);
	do_test_holding_cell_htlc_add_timeouts(true);
}

macro_rules! check_spendable_outputs {
	($node: expr, $keysinterface: expr) => {
		{
			let mut events = $node.chain_monitor.chain_monitor.get_and_clear_pending_events();
			let mut txn = Vec::new();
			let mut all_outputs = Vec::new();
			let secp_ctx = Secp256k1::new();
			for event in events.drain(..) {
				match event {
					Event::SpendableOutputs { mut outputs, channel_id: _ } => {
						for outp in outputs.drain(..) {
							txn.push($keysinterface.backing.spend_spendable_outputs(&[&outp], Vec::new(), Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, None, &secp_ctx).unwrap());
							all_outputs.push(outp);
						}
					},
					_ => panic!("Unexpected event"),
				};
			}
			if all_outputs.len() > 1 {
				if let Ok(tx) = $keysinterface.backing.spend_spendable_outputs(&all_outputs.iter().map(|a| a).collect::<Vec<_>>(), Vec::new(), Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, None, &secp_ctx) {
					txn.push(tx);
				}
			}
			txn
		}
	}
}

#[test]
fn test_claim_sizeable_push_msat() {
	// Incidentally test SpendableOutput event generation due to detection of to_local output on commitment tx
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 98_000_000);
	let error_message = "Channel force-closed";
	nodes[1].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[0].node.get_our_node_id()], 100000);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], BREAKDOWN_TIMEOUT as u32 - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
	assert_eq!(spend_txn[0].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
}

#[test]
fn test_claim_on_remote_sizeable_push_msat() {
	// Same test as previous, just test on remote commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let error_message = "Channel force-closed";

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 98_000_000);
	nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[1].node.get_our_node_id()], 100000);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	mine_transaction(&nodes[1], &node_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_claim_on_remote_revoked_sizeable_push_msat() {
	// Same test as previous, just test on remote revoked commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000);
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // to_remote output on revoked remote commitment_tx
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[0]); // Both outputs
}

#[test]
fn test_static_spendable_outputs_preimage_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// Settle A's commitment tx on B's chain
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);
	check_added_monitors!(nodes[1], 1);
	mine_transaction(&nodes[1], &commitment_tx[0]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}

	// Check B's monitor was able to send back output descriptor event for preimage tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: preimage tx
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);

	mine_transaction(&nodes[1], &node_txn[0]);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_static_spendable_outputs_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	let (_, our_payment_hash, ..) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3_000_000);

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// Settle A's commitment tx on B' chain
	mine_transaction(&nodes[1], &commitment_tx[0]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}
	connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	// Check B's monitor was able to send back output descriptor event for timeout tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1); // ChannelMonitor: timeout tx
	check_spends!(node_txn[0],  commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);

	mine_transaction(&nodes[1], &node_txn[0]);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[1], our_payment_hash, false);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 3); // SpendableOutput: remote_commitment_tx.to_remote, timeout_tx.output
	check_spends!(spend_txn[0], commitment_tx[0]);
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], node_txn[0], commitment_tx[0]); // All outputs
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_commitment_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1);
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0]);

	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_timeout_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	// A will generate HTLC-Timeout from revoked commitment tx
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let revoked_htlc_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(revoked_htlc_txn.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);
	assert_ne!(revoked_htlc_txn[0].lock_time, LockTime::ZERO); // HTLC-Timeout

	// B will generate justice tx from A's revoked commitment/HTLC tx
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()]));
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 2); // ChannelMonitor: bogus justice tx, justice tx on revoked outputs
	// The first transaction generated is bogus - it spends both outputs of revoked_local_txn[0]
	// including the one already spent by revoked_htlc_txn[1]. That's OK, we'll spend with valid
	// transactions next...
	assert_eq!(node_txn[0].input.len(), 3);
	check_spends!(node_txn[0], revoked_local_txn[0], revoked_htlc_txn[0]);

	assert_eq!(node_txn[1].input.len(), 2);
	check_spends!(node_txn[1], revoked_local_txn[0], revoked_htlc_txn[0]);
	if node_txn[1].input[1].previous_output.txid == revoked_htlc_txn[0].compute_txid() {
		assert_ne!(node_txn[1].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	} else {
		assert_eq!(node_txn[1].input[0].previous_output.txid, revoked_htlc_txn[0].compute_txid());
		assert_ne!(node_txn[1].input[1].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	}

	mine_transaction(&nodes[1], &node_txn[1]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	// Check B's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_txn[1]);
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_success_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// The to-be-revoked commitment tx should have one HTLC and one to_remote output
	assert_eq!(revoked_local_txn[0].output.len(), 2);

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	// B will generate HTLC-Success from revoked commitment tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();

	assert_eq!(revoked_htlc_txn.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);

	// Check that the unspent (of two) outputs on revoked_local_txn[0] is a P2WPKH:
	let unspent_local_txn_output = revoked_htlc_txn[0].input[0].previous_output.vout as usize ^ 1;
	assert_eq!(revoked_local_txn[0].output[unspent_local_txn_output].script_pubkey.len(), 2 + 20); // P2WPKH

	// A will generate justice tx from B's revoked commitment/HTLC tx
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()]));
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 2); // ChannelMonitor: justice tx on revoked commitment, justice tx on revoked HTLC-success

	// The first transaction generated is bogus - it spends both outputs of revoked_local_txn[0]
	// including the one already spent by revoked_htlc_txn[0]. That's OK, we'll spend with valid
	// transactions next...
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0], revoked_htlc_txn[0]);
	if node_txn[0].input[1].previous_output.txid == revoked_htlc_txn[0].compute_txid() {
		assert_eq!(node_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	} else {
		assert_eq!(node_txn[0].input[0].previous_output.txid, revoked_htlc_txn[0].compute_txid());
		assert_eq!(node_txn[0].input[1].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	}

	assert_eq!(node_txn[1].input.len(), 1);
	check_spends!(node_txn[1], revoked_htlc_txn[0]);

	mine_transaction(&nodes[0], &node_txn[1]);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	// Note that nodes[0]'s tx_broadcaster is still locked, so if we get here the channelmonitor
	// didn't try to generate any new transactions.

	// Check A's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // spending to_remote output from revoked local tx
	assert_ne!(spend_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	check_spends!(spend_txn[1], node_txn[1]); // spending justice tx output on the htlc success tx
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[1]); // Both outputs
}

#[test]
fn test_onchain_to_onchain_claim() {
	// Test that in case of channel closure, we detect the state of output and claim HTLC
	// on downstream peer's remote commitment tx.
	// First, have C claim an HTLC against its own latest commitment transaction.
	// Then, broadcast these to B, which should update the monitor downstream on the A<->B
	// channel.
	// Finally, check that B will claim the HTLC output if A's latest commitment transaction
	// gets broadcast.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Ensure all nodes are at the same height
	let node_max_height = nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());

	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors!(nodes[2], 1);
	check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	let c_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: 1 (HTLC-Success tx)
	assert_eq!(c_txn.len(), 1);
	check_spends!(c_txn[0], commitment_tx[0]);
	assert_eq!(c_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(c_txn[0].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert_eq!(c_txn[0].lock_time, LockTime::ZERO); // Success tx

	// So we broadcast C's commitment tx and HTLC-Success on B's chain, we should successfully be able to extract preimage and update downstream monitor
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![commitment_tx[0].clone(), c_txn[0].clone()]));
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentForwarded { total_fee_earned_msat, prev_channel_id, claim_from_onchain_tx,
			next_channel_id, outbound_amount_forwarded_msat, ..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, Some(chan_1.2));
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[1], 1);
	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	let nodes_2_event = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut msg_events);
	let nodes_0_event = remove_first_msg_event_to_node(&nodes[0].node.get_our_node_id(), &mut msg_events);

	match nodes_2_event {
		MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { .. }, node_id: _ } => {},
		_ => panic!("Unexpected event"),
	}

	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match msg_events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Broadcast A's commitment tx on B's chain to see if we are able to claim inbound HTLC with our HTLC-Success tx
	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	mine_transaction(&nodes[1], &commitment_tx[0]);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	let b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	// ChannelMonitor: HTLC-Success tx
	assert_eq!(b_txn.len(), 1);
	check_spends!(b_txn[0], commitment_tx[0]);
	assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert!(b_txn[0].output[0].script_pubkey.is_p2wpkh()); // direct payment
	assert_eq!(b_txn[0].lock_time.to_consensus_u32(), nodes[1].best_block_info().1); // Success tx

	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_duplicate_payment_hash_one_failure_one_success() {
	// Topology : A --> B --> C --> D
	// We route 2 payments with same hash between B and C, one will be timeout, the other successfully claim
	// Note that because C will refuse to generate two payment secrets for the same payment hash,
	// we forward one of the payments onwards to D.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	create_announced_chan_between_nodes(&nodes, 2, 3);

	let node_max_height = nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], node_max_height - nodes[3].best_block_info().1);

	let (our_payment_preimage, duplicate_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 900_000);

	let payment_secret = nodes[3].node.create_inbound_payment_for_hash(duplicate_payment_hash, None, 7200, None).unwrap();
	// We reduce the final CLTV here by a somewhat arbitrary constant to keep it under the one-byte
	// script push size limit so that the below script length checks match
	// ACCEPTED_HTLC_SCRIPT_WEIGHT.
	let payment_params = PaymentParameters::from_node_id(nodes[3].node.get_our_node_id(), TEST_FINAL_CLTV - 40)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features()).unwrap();
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[3], payment_params, 800_000);
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[2], &nodes[3]]], 800_000, duplicate_payment_hash, payment_secret);

	let commitment_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_txn[0].input.len(), 1);
	check_spends!(commitment_txn[0], chan_2.3);

	mine_transaction(&nodes[1], &commitment_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], TEST_FINAL_CLTV - 40 + MIN_CLTV_EXPIRY_DELTA as u32); // Confirm blocks until the HTLC expires

	let htlc_timeout_tx;
	{ // Extract one of the two HTLC-Timeout transaction
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// ChannelMonitor: timeout tx * 2-or-3
		assert!(node_txn.len() == 2 || node_txn.len() == 3);

		check_spends!(node_txn[0], commitment_txn[0]);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].output.len(), 1);

		if node_txn.len() > 2 {
			check_spends!(node_txn[1], commitment_txn[0]);
			assert_eq!(node_txn[1].input.len(), 1);
			assert_eq!(node_txn[1].output.len(), 1);
			assert_eq!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);

			check_spends!(node_txn[2], commitment_txn[0]);
			assert_eq!(node_txn[2].input.len(), 1);
			assert_eq!(node_txn[2].output.len(), 1);
			assert_ne!(node_txn[0].input[0].previous_output, node_txn[2].input[0].previous_output);
		} else {
			check_spends!(node_txn[1], commitment_txn[0]);
			assert_eq!(node_txn[1].input.len(), 1);
			assert_eq!(node_txn[1].output.len(), 1);
			assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		}

		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		// Assign htlc_timeout_tx to the forwarded HTLC (with value ~800 sats). The received HTLC
		// (with value 900 sats) will be claimed in the below `claim_funds` call.
		if node_txn.len() > 2 {
			assert_eq!(node_txn[2].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
			htlc_timeout_tx = if node_txn[2].output[0].value.to_sat() < 900 { node_txn[2].clone() } else { node_txn[0].clone() };
		} else {
			htlc_timeout_tx = if node_txn[0].output[0].value.to_sat() < 900 { node_txn[1].clone() } else { node_txn[0].clone() };
		}
	}

	nodes[2].node.claim_funds(our_payment_preimage);
	expect_payment_claimed!(nodes[2], duplicate_payment_hash, 900_000);

	mine_transaction(&nodes[2], &commitment_txn[0]);
	check_added_monitors!(nodes[2], 2);
	check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let htlc_success_txn: Vec<_> = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(htlc_success_txn.len(), 2); // ChannelMonitor: HTLC-Success txn (*2 due to 2-HTLC outputs)
	check_spends!(htlc_success_txn[0], commitment_txn[0]);
	check_spends!(htlc_success_txn[1], commitment_txn[0]);
	assert_eq!(htlc_success_txn[0].input.len(), 1);
	assert_eq!(htlc_success_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(htlc_success_txn[1].input.len(), 1);
	assert_eq!(htlc_success_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_ne!(htlc_success_txn[0].input[0].previous_output, htlc_success_txn[1].input[0].previous_output);
	assert_ne!(htlc_success_txn[1].input[0].previous_output, htlc_timeout_tx.input[0].previous_output);

	mine_transaction(&nodes[1], &htlc_timeout_tx);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	let first_htlc_id = htlc_updates.update_fail_htlcs[0].htlc_id;
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	{
		commitment_signed_dance!(nodes[0], nodes[1], &htlc_updates.commitment_signed, false, true);
	}
	expect_payment_failed_with_update!(nodes[0], duplicate_payment_hash, false, chan_2.0.contents.short_channel_id, true);

	// Solve 2nd HTLC by broadcasting on B's chain HTLC-Success Tx from C
	mine_transaction(&nodes[1], &htlc_success_txn[1]);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(196), true, true);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert_ne!(updates.update_fulfill_htlcs[0].htlc_id, first_htlc_id);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], &updates.commitment_signed, false);
	expect_payment_sent(&nodes[0], our_payment_preimage, None, true, true);
}

#[test]
fn test_dynamic_spendable_outputs_local_htlc_success_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);
	let local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(local_txn.len(), 1);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Give B knowledge of preimage to be able to generate a local HTLC-Success Tx
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 9_000_000);
	check_added_monitors!(nodes[1], 1);

	mine_transaction(&nodes[1], &local_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let node_tx = {
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[1], &node_tx);
	connect_blocks(&nodes[1], BREAKDOWN_TIMEOUT as u32 - 1);

	// Verify that B is able to spend its own HTLC-Success tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_tx);
	assert_eq!(spend_txn[0].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
}

fn do_test_fail_backwards_unrevoked_remote_announce(deliver_last_raa: bool, announce_latest: bool) {
	// Test that we fail backwards the full set of HTLCs we need to when remote broadcasts an
	// unrevoked commitment transaction.
	// This includes HTLCs which were below the dust threshold as well as HTLCs which were awaiting
	// a remote RAA before they could be failed backwards (and combinations thereof).
	// We also test duplicate-hash HTLCs by adding two nodes on each side of the target nodes which
	// use the same payment hashes.
	// Thus, we use a six-node network:
	//
	// A \         / E
	//    - C - D -
	// B /         \ F
	// And test where C fails back to A/B when D announces its latest commitment transaction
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config.clone()), Some(config.clone()), Some(config.clone()), Some(config.clone())]);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	let _chan_0_2 = create_announced_chan_between_nodes(&nodes, 0, 2);
	let _chan_1_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_2_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_3_4 = create_announced_chan_between_nodes(&nodes, 3, 4);
	let chan_3_5  = create_announced_chan_between_nodes(&nodes, 3, 5);

	// Rebalance and check output sanity...
	send_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 500000);
	send_payment(&nodes[1], &[&nodes[2], &nodes[3], &nodes[5]], 500000);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2)[0].output.len(), 2);

	let ds_dust_limit = nodes[3].node.per_peer_state.read().unwrap().get(&nodes[2].node.get_our_node_id())
		.unwrap().lock().unwrap().channel_by_id.get(&chan_2_3.2).unwrap().context().holder_dust_limit_satoshis;
	// 0th HTLC:
	let (_, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 1st HTLC:
	let (_, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], ds_dust_limit*1000);
	// 2nd HTLC:
	send_along_route_with_secret(&nodes[1], route.clone(), &[&[&nodes[2], &nodes[3], &nodes[5]]], ds_dust_limit*1000, payment_hash_1, nodes[5].node.create_inbound_payment_for_hash(payment_hash_1, None, 7200, None).unwrap()); // not added < dust limit + HTLC tx fee
	// 3rd HTLC:
	send_along_route_with_secret(&nodes[1], route, &[&[&nodes[2], &nodes[3], &nodes[5]]], ds_dust_limit*1000, payment_hash_2, nodes[5].node.create_inbound_payment_for_hash(payment_hash_2, None, 7200, None).unwrap()); // not added < dust limit + HTLC tx fee
	// 4th HTLC:
	let (_, payment_hash_3, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 5th HTLC:
	let (_, payment_hash_4, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], 1000000);
	// 6th HTLC:
	send_along_route_with_secret(&nodes[1], route.clone(), &[&[&nodes[2], &nodes[3], &nodes[5]]], 1000000, payment_hash_3, nodes[5].node.create_inbound_payment_for_hash(payment_hash_3, None, 7200, None).unwrap());
	// 7th HTLC:
	send_along_route_with_secret(&nodes[1], route, &[&[&nodes[2], &nodes[3], &nodes[5]]], 1000000, payment_hash_4, nodes[5].node.create_inbound_payment_for_hash(payment_hash_4, None, 7200, None).unwrap());

	// 8th HTLC:
	let (_, payment_hash_5, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 9th HTLC:
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], ds_dust_limit*1000);
	send_along_route_with_secret(&nodes[1], route, &[&[&nodes[2], &nodes[3], &nodes[5]]], ds_dust_limit*1000, payment_hash_5, nodes[5].node.create_inbound_payment_for_hash(payment_hash_5, None, 7200, None).unwrap()); // not added < dust limit + HTLC tx fee

	// 10th HTLC:
	let (_, payment_hash_6, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 11th HTLC:
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], 1000000);
	send_along_route_with_secret(&nodes[1], route, &[&[&nodes[2], &nodes[3], &nodes[5]]], 1000000, payment_hash_6, nodes[5].node.create_inbound_payment_for_hash(payment_hash_6, None, 7200, None).unwrap());

	// Double-check that six of the new HTLC were added
	// We now have six HTLCs pending over the dust limit and six HTLCs under the dust limit (ie,
	// with to_local and to_remote outputs, 8 outputs and 6 HTLCs not included).
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2).len(), 1);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2)[0].output.len(), 8);

	// Now fail back three of the over-dust-limit and three of the under-dust-limit payments in one go.
	// Fail 0th below-dust, 4th above-dust, 8th above-dust, 10th below-dust HTLCs
	nodes[4].node.fail_htlc_backwards(&payment_hash_1);
	nodes[4].node.fail_htlc_backwards(&payment_hash_3);
	nodes[4].node.fail_htlc_backwards(&payment_hash_5);
	nodes[4].node.fail_htlc_backwards(&payment_hash_6);
	check_added_monitors!(nodes[4], 0);

	let failed_destinations = vec![
		HTLCDestination::FailedPayment { payment_hash: payment_hash_1 },
		HTLCDestination::FailedPayment { payment_hash: payment_hash_3 },
		HTLCDestination::FailedPayment { payment_hash: payment_hash_5 },
		HTLCDestination::FailedPayment { payment_hash: payment_hash_6 },
	];
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[4], failed_destinations);
	check_added_monitors!(nodes[4], 1);

	let four_removes = get_htlc_update_msgs!(nodes[4], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[1]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[2]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[3]);
	commitment_signed_dance!(nodes[3], nodes[4], four_removes.commitment_signed, false);

	// Fail 3rd below-dust and 7th above-dust HTLCs
	nodes[5].node.fail_htlc_backwards(&payment_hash_2);
	nodes[5].node.fail_htlc_backwards(&payment_hash_4);
	check_added_monitors!(nodes[5], 0);

	let failed_destinations_2 = vec![
		HTLCDestination::FailedPayment { payment_hash: payment_hash_2 },
		HTLCDestination::FailedPayment { payment_hash: payment_hash_4 },
	];
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[5], failed_destinations_2);
	check_added_monitors!(nodes[5], 1);

	let two_removes = get_htlc_update_msgs!(nodes[5], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[1]);
	commitment_signed_dance!(nodes[3], nodes[5], two_removes.commitment_signed, false);

	let ds_prev_commitment_tx = get_local_commitment_txn!(nodes[3], chan_2_3.2);

	// After 4 and 2 removes respectively above in nodes[4] and nodes[5], nodes[3] should receive 6 PaymentForwardedFailed events
	let failed_destinations_3 = vec![
		HTLCDestination::NextHopChannel { node_id: Some(nodes[4].node.get_our_node_id()), channel_id: chan_3_4.2 },
		HTLCDestination::NextHopChannel { node_id: Some(nodes[4].node.get_our_node_id()), channel_id: chan_3_4.2 },
		HTLCDestination::NextHopChannel { node_id: Some(nodes[4].node.get_our_node_id()), channel_id: chan_3_4.2 },
		HTLCDestination::NextHopChannel { node_id: Some(nodes[4].node.get_our_node_id()), channel_id: chan_3_4.2 },
		HTLCDestination::NextHopChannel { node_id: Some(nodes[5].node.get_our_node_id()), channel_id: chan_3_5.2 },
		HTLCDestination::NextHopChannel { node_id: Some(nodes[5].node.get_our_node_id()), channel_id: chan_3_5.2 },
	];
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[3], failed_destinations_3);
	check_added_monitors!(nodes[3], 1);
	let six_removes = get_htlc_update_msgs!(nodes[3], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[0]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[1]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[2]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[3]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[4]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[5]);
	if deliver_last_raa {
		commitment_signed_dance!(nodes[2], nodes[3], six_removes.commitment_signed, false);
	} else {
		let _cs_last_raa = commitment_signed_dance!(nodes[2], nodes[3], six_removes.commitment_signed, false, true, false, true);
	}

	// D's latest commitment transaction now contains 1st + 2nd + 9th HTLCs (implicitly, they're
	// below the dust limit) and the 5th + 6th + 11th HTLCs. It has failed back the 0th, 3rd, 4th,
	// 7th, 8th, and 10th, but as we haven't yet delivered the final RAA to C, the fails haven't
	// propagated back to A/B yet (and D has two unrevoked commitment transactions).
	//
	// We now broadcast the latest commitment transaction, which *should* result in failures for
	// the 0th, 1st, 2nd, 3rd, 4th, 7th, 8th, 9th, and 10th HTLCs, ie all the below-dust HTLCs and
	// the non-broadcast above-dust HTLCs.
	//
	// Alternatively, we may broadcast the previous commitment transaction, which should only
	// result in failures for the below-dust HTLCs, ie the 0th, 1st, 2nd, 3rd, 9th, and 10th HTLCs.
	let ds_last_commitment_tx = get_local_commitment_txn!(nodes[3], chan_2_3.2);

	if announce_latest {
		mine_transaction(&nodes[2], &ds_last_commitment_tx[0]);
	} else {
		mine_transaction(&nodes[2], &ds_prev_commitment_tx[0]);
	}
	let events = nodes[2].node.get_and_clear_pending_events();
	let close_event = if deliver_last_raa {
		assert_eq!(events.len(), 2 + 6);
		events.last().clone().unwrap()
	} else {
		assert_eq!(events.len(), 1);
		events.last().clone().unwrap()
	};
	match close_event {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
		_ => panic!("Unexpected event"),
	}

	connect_blocks(&nodes[2], ANTI_REORG_DELAY - 1);
	check_closed_broadcast!(nodes[2], true);
	if deliver_last_raa {
		expect_pending_htlcs_forwardable_from_events!(nodes[2], events[1..2], true);

		let expected_destinations: Vec<HTLCDestination> = repeat(HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_2_3.2 }).take(3).collect();
		expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), expected_destinations);
	} else {
		let expected_destinations: Vec<HTLCDestination> = if announce_latest {
			repeat(HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_2_3.2 }).take(9).collect()
		} else {
			repeat(HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_2_3.2 }).take(6).collect()
		};

		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], expected_destinations);
	}
	check_added_monitors!(nodes[2], 3);

	let cs_msgs = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(cs_msgs.len(), 2);
	let mut a_done = false;
	for msg in cs_msgs {
		match msg {
			MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
				// Both under-dust HTLCs and the one above-dust HTLC that we had already failed
				// should be failed-backwards here.
				let target = if *node_id == nodes[0].node.get_our_node_id() {
					// If announce_latest, expect 0th, 1st, 4th, 8th, 10th HTLCs, else only 0th, 1st, 10th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(htlc.htlc_id == 1 || htlc.htlc_id == 2 || htlc.htlc_id == 6 || if announce_latest { htlc.htlc_id == 3 || htlc.htlc_id == 5 } else { false });
					}
					assert_eq!(updates.update_fail_htlcs.len(), if announce_latest { 5 } else { 3 });
					assert!(!a_done);
					a_done = true;
					&nodes[0]
				} else {
					// If announce_latest, expect 2nd, 3rd, 7th, 9th HTLCs, else only 2nd, 3rd, 9th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(htlc.htlc_id == 1 || htlc.htlc_id == 2 || htlc.htlc_id == 5 || if announce_latest { htlc.htlc_id == 4 } else { false });
					}
					assert_eq!(*node_id, nodes[1].node.get_our_node_id());
					assert_eq!(updates.update_fail_htlcs.len(), if announce_latest { 4 } else { 3 });
					&nodes[1]
				};
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[1]);
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[2]);
				if announce_latest {
					target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[3]);
					if *node_id == nodes[0].node.get_our_node_id() {
						target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[4]);
					}
				}
				commitment_signed_dance!(target, nodes[2], updates.commitment_signed, false, true);
			},
			_ => panic!("Unexpected event"),
		}
	}

	let as_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(as_events.len(), if announce_latest { 10 } else { 6 });
	let mut as_faileds = new_hash_set();
	let mut as_updates = 0;
	for event in as_events.iter() {
		if let &Event::PaymentPathFailed { ref payment_hash, ref payment_failed_permanently, ref failure, .. } = event {
			assert!(as_faileds.insert(*payment_hash));
			if *payment_hash != payment_hash_2 {
				assert_eq!(*payment_failed_permanently, deliver_last_raa);
			} else {
				assert!(!payment_failed_permanently);
			}
			if let PathFailure::OnPath { network_update: Some(_) } = failure {
				as_updates += 1;
			}
		} else if let &Event::PaymentFailed { .. } = event {
		} else { panic!("Unexpected event"); }
	}
	assert!(as_faileds.contains(&payment_hash_1));
	assert!(as_faileds.contains(&payment_hash_2));
	if announce_latest {
		assert!(as_faileds.contains(&payment_hash_3));
		assert!(as_faileds.contains(&payment_hash_5));
	}
	assert!(as_faileds.contains(&payment_hash_6));

	let bs_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(bs_events.len(), if announce_latest { 8 } else { 6 });
	let mut bs_faileds = new_hash_set();
	let mut bs_updates = 0;
	for event in bs_events.iter() {
		if let &Event::PaymentPathFailed { ref payment_hash, ref payment_failed_permanently, ref failure, .. } = event {
			assert!(bs_faileds.insert(*payment_hash));
			if *payment_hash != payment_hash_1 && *payment_hash != payment_hash_5 {
				assert_eq!(*payment_failed_permanently, deliver_last_raa);
			} else {
				assert!(!payment_failed_permanently);
			}
			if let PathFailure::OnPath { network_update: Some(_) } = failure {
				bs_updates += 1;
			}
		} else if let &Event::PaymentFailed { .. } = event {
		} else { panic!("Unexpected event"); }
	}
	assert!(bs_faileds.contains(&payment_hash_1));
	assert!(bs_faileds.contains(&payment_hash_2));
	if announce_latest {
		assert!(bs_faileds.contains(&payment_hash_4));
	}
	assert!(bs_faileds.contains(&payment_hash_5));

	// For each HTLC which was not failed-back by normal process (ie deliver_last_raa), we should
	// get a NetworkUpdate. A should have gotten 4 HTLCs which were failed-back due to
	// unknown-preimage-etc, B should have gotten 2. Thus, in the
	// announce_latest && deliver_last_raa case, we should have 5-4=1 and 4-2=2 NetworkUpdates.
	assert_eq!(as_updates, if deliver_last_raa { 1 } else if !announce_latest { 3 } else { 5 });
	assert_eq!(bs_updates, if deliver_last_raa { 2 } else if !announce_latest { 3 } else { 4 });
}

#[test]
fn test_fail_backwards_latest_remote_announce_a() {
	do_test_fail_backwards_unrevoked_remote_announce(false, true);
}

#[test]
fn test_fail_backwards_latest_remote_announce_b() {
	do_test_fail_backwards_unrevoked_remote_announce(true, true);
}

#[test]
fn test_fail_backwards_previous_remote_announce() {
	do_test_fail_backwards_unrevoked_remote_announce(false, false);
	// Note that true, true doesn't make sense as it implies we announce a revoked state, which is
	// tested for in test_commitment_revoked_fail_backward_exhaustive()
}

#[test]
fn test_dynamic_spendable_outputs_local_htlc_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	mine_transaction(&nodes[0], &local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[0], &htlc_timeout);
	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	expect_payment_failed!(nodes[0], our_payment_hash, false);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn[0]);
	assert_eq!(spend_txn[1].input.len(), 1);
	check_spends!(spend_txn[1], htlc_timeout);
	assert_eq!(spend_txn[1].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
	assert_eq!(spend_txn[2].input.len(), 2);
	check_spends!(spend_txn[2], local_txn[0], htlc_timeout);
	assert!(spend_txn[2].input[0].sequence.0 == BREAKDOWN_TIMEOUT as u32 ||
	        spend_txn[2].input[1].sequence.0 == BREAKDOWN_TIMEOUT as u32);
}

#[test]
fn test_key_derivation_params() {
	// This test is a copy of test_dynamic_spendable_outputs_local_htlc_timeout_tx, with a key
	// manager rotation to test that `channel_keys_id` returned in
	// [`SpendableOutputDescriptor::DelayedPaymentOutput`] let us re-derive the channel key set to
	// then derive a `delayed_payment_key`.

	let chanmon_cfgs = create_chanmon_cfgs(3);

	// We manually create the node configuration to backup the seed.
	let seed = [42; 32];
	let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let chain_monitor = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &chanmon_cfgs[0].persister, &keys_manager);
	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &chanmon_cfgs[0].logger));
	let scorer = RwLock::new(test_utils::TestScorer::new());
	let router = test_utils::TestRouter::new(network_graph.clone(), &chanmon_cfgs[0].logger, &scorer);
	let message_router = test_utils::TestMessageRouter::new(network_graph.clone(), &keys_manager);
	let node = NodeCfg { chain_source: &chanmon_cfgs[0].chain_source, logger: &chanmon_cfgs[0].logger, tx_broadcaster: &chanmon_cfgs[0].tx_broadcaster, fee_estimator: &chanmon_cfgs[0].fee_estimator, router, message_router, chain_monitor, keys_manager: &keys_manager, network_graph, node_seed: seed, override_init_features: alloc::rc::Rc::new(core::cell::RefCell::new(None)) };
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	node_cfgs.remove(0);
	node_cfgs.insert(0, node);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	// Create a dummy channel to advance index by one and thus test re-derivation correctness
	// for node 0
	let chan_0 = create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	assert_ne!(chan_0.3.output[0].script_pubkey, chan_1.3.output[0].script_pubkey);

	// Ensure all nodes are at the same height
	let node_max_height = nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000);
	let local_txn_0 = get_local_commitment_txn!(nodes[0], chan_0.2);
	let local_txn_1 = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn_1[0].input.len(), 1);
	check_spends!(local_txn_1[0], chan_1.3);

	// We check funding pubkey are unique
	let (from_0_funding_key_0, from_0_funding_key_1) = (PublicKey::from_slice(&local_txn_0[0].input[0].witness.to_vec()[3][2..35]), PublicKey::from_slice(&local_txn_0[0].input[0].witness.to_vec()[3][36..69]));
	let (from_1_funding_key_0, from_1_funding_key_1) = (PublicKey::from_slice(&local_txn_1[0].input[0].witness.to_vec()[3][2..35]), PublicKey::from_slice(&local_txn_1[0].input[0].witness.to_vec()[3][36..69]));
	if from_0_funding_key_0 == from_1_funding_key_0
	    || from_0_funding_key_0 == from_1_funding_key_1
	    || from_0_funding_key_1 == from_1_funding_key_0
	    || from_0_funding_key_1 == from_1_funding_key_1 {
		panic!("Funding pubkeys aren't unique");
	}

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	mine_transaction(&nodes[0], &local_txn_1[0]);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn_1[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[0], &htlc_timeout);
	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	expect_payment_failed!(nodes[0], our_payment_hash, false);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let new_keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let spend_txn = check_spendable_outputs!(nodes[0], new_keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn_1[0]);
	assert_eq!(spend_txn[1].input.len(), 1);
	check_spends!(spend_txn[1], htlc_timeout);
	assert_eq!(spend_txn[1].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
	assert_eq!(spend_txn[2].input.len(), 2);
	check_spends!(spend_txn[2], local_txn_1[0], htlc_timeout);
	assert!(spend_txn[2].input[0].sequence.0 == BREAKDOWN_TIMEOUT as u32 ||
	        spend_txn[2].input[1].sequence.0 == BREAKDOWN_TIMEOUT as u32);
}

#[test]
fn test_static_output_closing_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

	mine_transaction(&nodes[0], &closing_tx);
	check_closed_event!(nodes[0], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);

	mine_transaction(&nodes[1], &closing_tx);
	check_closed_event!(nodes[1], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);
}

fn do_htlc_claim_local_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], if use_dust { 50000 } else { 3_000_000 });

	// Claim the payment, but don't deliver A's commitment_signed, resulting in the HTLC only being
	// present in B's local commitment transaction, but none of A's commitment transactions.
	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, if use_dust { 50000 } else { 3_000_000 });

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fulfill_htlcs[0]);
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0);
	check_added_monitors!(nodes[1], 1);

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());
	for _ in starting_block.1 + 1..TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + starting_block.1 + 2 {
		connect_block(&nodes[1], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	test_txn_broadcast(&nodes[1], &chan, None, if use_dust { HTLCType::NONE } else { HTLCType::SUCCESS });
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::HTLCsTimedOut, [nodes[0].node.get_our_node_id()], 100000);
}

fn do_htlc_claim_current_remote_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], if use_dust { 50000 } else { 3000000 });
	nodes[0].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let _as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// As far as A is concerned, the HTLC is now present only in the latest remote commitment
	// transaction, however it is not in A's latest local commitment, so we can just broadcast that
	// to "time out" the HTLC.

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());

	for _ in starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + starting_block.1 + 2 {
		connect_block(&nodes[0], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HTLCsTimedOut, [nodes[1].node.get_our_node_id()], 100000);
}

fn do_htlc_claim_previous_remote_commitment_only(use_dust: bool, check_revoke_no_close: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Fail the payment, but don't deliver A's final RAA, resulting in the HTLC only being present
	// in B's previous (unrevoked) commitment transaction, but none of A's commitment transactions.
	// Also optionally test that we *don't* fail the channel in case the commitment transaction was
	// actually revoked.
	let htlc_value = if use_dust { 50000 } else { 3000000 };
	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], htlc_value);
	nodes[1].node.fail_htlc_backwards(&our_payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_updates.1);
	check_added_monitors!(nodes[1], 1);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	if check_revoke_no_close {
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
		check_added_monitors!(nodes[0], 1);
	}

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());
	for _ in starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + CHAN_CONFIRM_DEPTH + 2 {
		connect_block(&nodes[0], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	if !check_revoke_no_close {
		test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::HTLCsTimedOut, [nodes[1].node.get_our_node_id()], 100000);
	} else {
		expect_payment_failed!(nodes[0], our_payment_hash, true);
	}
}

// Test that we close channels on-chain when broadcastable HTLCs reach their timeout window.
// There are only a few cases to test here:
//  * its not really normative behavior, but we test that below-dust HTLCs "included" in
//    broadcastable commitment transactions result in channel closure,
//  * its included in an unrevoked-but-previous remote commitment transaction,
//  * its included in the latest remote or local commitment transactions.
// We test each of the three possible commitment transactions individually and use both dust and
// non-dust HTLCs.
// Note that we don't bother testing both outbound and inbound HTLC failures for each case, and we
// assume they are handled the same across all six cases, as both outbound and inbound failures are
// tested for at least one of the cases in other tests.
#[test]
fn htlc_claim_single_commitment_only_a() {
	do_htlc_claim_local_commitment_only(true);
	do_htlc_claim_local_commitment_only(false);

	do_htlc_claim_current_remote_commitment_only(true);
	do_htlc_claim_current_remote_commitment_only(false);
}

#[test]
fn htlc_claim_single_commitment_only_b() {
	do_htlc_claim_previous_remote_commitment_only(true, false);
	do_htlc_claim_previous_remote_commitment_only(false, false);
	do_htlc_claim_previous_remote_commitment_only(true, true);
	do_htlc_claim_previous_remote_commitment_only(false, true);
}

#[test]
#[should_panic]
fn bolt2_open_channel_sending_node_checks_part1() { //This test needs to be on its own as we are catching a panic
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	// Force duplicate randomness for every get-random call
	for node in nodes.iter() {
		*node.keys_manager.override_random_bytes.lock().unwrap() = Some([0; 32]);
	}

	// BOLT #2 spec: Sending node must ensure temporary_channel_id is unique from any other channel ID with the same peer.
	let channel_value_satoshis=10000;
	let push_msat=10001;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).unwrap();
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &node0_to_1_send_open_channel);
	get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	// Create a second channel with the same random values. This used to panic due to a colliding
	// channel_id, but now panics due to a colliding outbound SCID alias.
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).is_err());
}

#[test]
fn bolt2_open_channel_sending_node_checks_part2() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// BOLT #2 spec: Sending node must set funding_satoshis to less than 2^24 satoshis
	let channel_value_satoshis=2^24;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).is_err());

	// BOLT #2 spec: Sending node must set push_msat to equal or less than 1000 * funding_satoshis
	let channel_value_satoshis=10000;
	// Test when push_msat is equal to 1000 * funding_satoshis.
	let push_msat=1000*channel_value_satoshis+1;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).is_err());

	// BOLT #2 spec: Sending node must set set channel_reserve_satoshis greater than or equal to dust_limit_satoshis
	let channel_value_satoshis=10000;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).is_ok()); //Create a valid channel
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(node0_to_1_send_open_channel.channel_reserve_satoshis>=node0_to_1_send_open_channel.common_fields.dust_limit_satoshis);

	// BOLT #2 spec: Sending node must set undefined bits in channel_flags to 0
	// Only the least-significant bit of channel_flags is currently defined resulting in channel_flags only having one of two possible states 0 or 1
	assert!(node0_to_1_send_open_channel.common_fields.channel_flags<=1);

	// BOLT #2 spec: Sending node should set to_self_delay sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehaviour by the receiver.
	assert!(BREAKDOWN_TIMEOUT>0);
	assert!(node0_to_1_send_open_channel.common_fields.to_self_delay==BREAKDOWN_TIMEOUT);

	// BOLT #2 spec: Sending node must ensure the chain_hash value identifies the chain it wishes to open the channel within.
	let chain_hash = ChainHash::using_genesis_block(Network::Testnet);
	assert_eq!(node0_to_1_send_open_channel.common_fields.chain_hash, chain_hash);

	// BOLT #2 spec: Sending node must set funding_pubkey, revocation_basepoint, htlc_basepoint, payment_basepoint, and delayed_payment_basepoint to valid DER-encoded, compressed, secp256k1 pubkeys.
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.common_fields.funding_pubkey.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.common_fields.revocation_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.common_fields.htlc_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.common_fields.payment_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.common_fields.delayed_payment_basepoint.serialize()).is_ok());
}

#[test]
fn bolt2_open_channel_sane_dust_limit() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel_value_satoshis=1000000;
	let push_msat=10001;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None, None).unwrap();
	let mut node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	node0_to_1_send_open_channel.common_fields.dust_limit_satoshis = 547;
	node0_to_1_send_open_channel.channel_reserve_satoshis = 100001;

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &node0_to_1_send_open_channel);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	let err_msg = match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};
	assert_eq!(err_msg.data, "dust_limit_satoshis (547) is greater than the implementation limit (546)");
}

// Test that if we fail to send an HTLC that is being freed from the holding cell, and the HTLC
// originated from our node, its failure is surfaced to the user. We trigger this failure to
// free the HTLC by increasing our fee while the HTLC is in the holding cell such that the HTLC
// is no longer affordable once it's freed.
#[test]
fn test_fail_holding_cell_htlc_upon_free() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let max_can_send = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], max_can_send);

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (as_revoke_and_ack, _) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack);
	check_added_monitors!(nodes[0], 1);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell
	// HTLC, but now that the fee has been raised the payment will now fail, causing
	// us to surface its failure to the user.
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log("lightning::ln::channel", format!("Freeing holding cell with 1 HTLC updates in channel {}", chan.2), 1);

	// Check that the payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		&Event::PaymentPathFailed { ref payment_id, ref payment_hash, ref payment_failed_permanently, failure: PathFailure::OnPath { network_update: None }, ref short_channel_id, .. } => {
			assert_eq!(PaymentId(our_payment_hash.0), *payment_id.as_ref().unwrap());
			assert_eq!(our_payment_hash.clone(), *payment_hash);
			assert_eq!(*payment_failed_permanently, false);
			assert_eq!(*short_channel_id, Some(route.paths[0].hops[0].short_channel_id));
		},
		_ => panic!("Unexpected event"),
	}
	match &events[1] {
		&Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(Some(our_payment_hash), *payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
}

// Test that if multiple HTLCs are released from the holding cell and one is
// valid but the other is no longer valid upon release, the valid HTLC can be
// successfully completed while the other one fails as expected.
#[test]
fn test_free_and_fail_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 200;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let amt_1 = 20000;
	let amt_2 = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 2 + 1, &channel_type_features) - amt_1;
	let (route_1, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], amt_1);
	let (route_2, payment_hash_2, _, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], amt_2);

	// Send 2 payments which pass reserve checks but get stuck in the holding cell.
	nodes[0].node.send_payment_with_route(route_1, payment_hash_1,
		RecipientOnionFields::secret_only(payment_secret_1), PaymentId(payment_hash_1.0)).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1);
	let payment_id_2 = PaymentId(nodes[0].keys_manager.get_secure_random_bytes());
	nodes[0].node.send_payment_with_route(route_2.clone(), payment_hash_2,
		RecipientOnionFields::secret_only(payment_secret_2), payment_id_2).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1 + amt_2);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_and_ack, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_and_ack);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[0], 2);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell HTLCs,
	// but now that the fee has been raised the second payment will now fail, causing us
	// to surface its failure to the user. The first payment should succeed.
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log("lightning::ln::channel", format!("Freeing holding cell with 2 HTLC updates in channel {}", chan.2), 1);

	// Check that the second payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		&Event::PaymentPathFailed { ref payment_id, ref payment_hash, ref payment_failed_permanently, failure: PathFailure::OnPath { network_update: None }, ref short_channel_id, .. } => {
			assert_eq!(payment_id_2, *payment_id.as_ref().unwrap());
			assert_eq!(payment_hash_2.clone(), *payment_hash);
			assert_eq!(*payment_failed_permanently, false);
			assert_eq!(*short_channel_id, Some(route_2.paths[0].hops[0].short_channel_id));
		},
		_ => panic!("Unexpected event"),
	}
	match &events[1] {
		&Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(Some(payment_hash_2), *payment_hash);
		},
		_ => panic!("Unexpected event"),
	}

	// Complete the first payment and the RAA from the fee update.
	let (payment_event, send_raa_event) = {
		let mut msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msgs.len(), 2);
		(SendEvent::from_event(msgs.remove(0)), msgs.remove(0))
	};
	let raa = match send_raa_event {
		MessageSendEvent::SendRevokeAndACK { msg, .. } => msg,
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}
	nodes[1].node.process_pending_htlc_forwards();
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { .. } => {},
		_ => panic!("Unexpected event"),
	}
	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, amt_1);

	let update_msgs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_msgs.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], update_msgs.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_1);
}

// Test that if we fail to forward an HTLC that is being freed from the holding cell that the
// HTLC is failed backwards. We trigger this failure to forward the freed HTLC by increasing
// our fee while the HTLC is in the holding cell such that the HTLC is no longer affordable
// once it's freed.
#[test]
fn test_fail_holding_cell_htlc_upon_free_multihop() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	// Avoid having to include routing fees in calculations
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 0;
	config.channel_config.forwarding_fee_proportional_millionths = 0;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config.clone()), Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_0_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 95000000);

	// First nodes[1] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[1].node.timer_tick_occurred();
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_update_fee(&nodes[1].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan_0_1.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan_0_1.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_0_1.2);

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	let max_can_send = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], max_can_send);
	let payment_event = {
		nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);

		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	chan_stat = get_channel_value_stat!(nodes[1], nodes[2], chan_1_2.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
	let (raa, commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[2], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &raa);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 2);

	// A final RAA message is generated to finalize the fee update.
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let raa_msg = match &events[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa_msg);
	check_added_monitors!(nodes[2], 1);
	assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

	// nodes[1]'s ChannelManager will now signal that we have HTLC forwards to process.
	let process_htlc_forwards_event = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(process_htlc_forwards_event.len(), 2);
	match &process_htlc_forwards_event[1] {
		&Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// In response, we call ChannelManager's process_pending_htlc_forwards
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[1], 1);

	// This causes the HTLC to be failed backwards.
	let fail_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(fail_event.len(), 1);
	let (fail_msg, commitment_signed) = match &fail_event[0] {
		&MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			assert_eq!(updates.update_add_htlcs.len(), 0);
			assert_eq!(updates.update_fulfill_htlcs.len(), 0);
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 0);
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			(updates.update_fail_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	// Pass the failure messages back to nodes[0].
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);

	// Complete the HTLC failure+removal process.
	let (raa, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 2);
	let final_raa_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(final_raa_event.len(), 1);
	let raa = match &final_raa_event[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => msg.clone(),
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa);
	expect_payment_failed_with_update!(nodes[0], our_payment_hash, false, chan_1_2.0.contents.short_channel_id, false);
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_payment_route_reaching_same_channel_twice() {
	//A route should not go through the same channel twice
	//It is enforced when constructing a route.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0);

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), 0)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features()).unwrap();
	let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], payment_params, 100000000);

	// Extend the path by itself, essentially simulating route going through same channel twice
	let cloned_hops = route.paths[0].hops.clone();
	route.paths[0].hops.extend_from_slice(&cloned_hops);

	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
	), false, APIError::InvalidRoute { ref err },
	assert_eq!(err, &"Path went through the same channel twice"));
}

// BOLT 2 Requirements for the Sender when constructing and sending an update_add_htlc message.
// BOLT 2 Requirement: MUST NOT offer amount_msat it cannot pay for in the remote commitment transaction at the current feerate_per_kw (see "Updating Fees") while maintaining its channel reserve.
//TODO: I don't believe this is explicitly enforced when sending an HTLC but as the Fee aspect of the BOLT specs is in flux leaving this as a TODO.

#[test]
fn test_update_add_htlc_bolt2_sender_value_below_minimum_msat() {
	//BOLT2 Requirement: MUST NOT offer amount_msat below the receiving node's htlc_minimum_msat (same validation check catches both of these)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
	route.paths[0].hops[0].fee_msat = 100;

	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_update_add_htlc_bolt2_sender_zero_value_msat() {
	//BOLT2 Requirement: MUST offer amount_msat greater than 0.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
	route.paths[0].hops[0].fee_msat = 0;
	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)),
		true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Cannot send 0-msat HTLC"));

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager", "Cannot send 0-msat HTLC", 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_zero_value_msat() {
	//BOLT2 Requirement: MUST offer amount_msat greater than 0.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = 0;

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Remote side tried to send a 0-msat HTLC", 3);
	check_closed_broadcast!(nodes[1], true).unwrap();
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: "Remote side tried to send a 0-msat HTLC".to_string() },
		[nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_add_htlc_bolt2_sender_cltv_expiry_too_high() {
	//BOLT 2 Requirement: MUST set cltv_expiry less than 500000000.
	//It is enforced when constructing a route.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0);

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), 0)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features()).unwrap();
	let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], payment_params, 100000000);
	route.paths[0].hops.last_mut().unwrap().cltv_expiry_delta = 500000001;
	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::InvalidRoute { ref err },
		assert_eq!(err, &"Channel CLTV overflowed?"));
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_num_and_htlc_id_increment() {
	//BOLT 2 Requirement: if result would be offering more than the remote's max_accepted_htlcs HTLCs, in the remote commitment transaction: MUST NOT add an HTLC.
	//BOLT 2 Requirement: for the first HTLC it offers MUST set id to 0.
	//BOLT 2 Requirement: MUST increase the value of id by 1 for each successive offer.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0);
	let max_accepted_htlcs = nodes[1].node.per_peer_state.read().unwrap().get(&nodes[0].node.get_our_node_id())
		.unwrap().lock().unwrap().channel_by_id.get(&chan.2).unwrap().context().counterparty_max_accepted_htlcs as u64;

	// Fetch a route in advance as we will be unable to once we're unable to send.
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
	for i in 0..max_accepted_htlcs {
		let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100000);
		let payment_event = {
			nodes[0].node.send_payment_with_route(route, our_payment_hash,
				RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
			check_added_monitors!(nodes[0], 1);

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			if let MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate{ update_add_htlcs: ref htlcs, .. }, } = events[0] {
				assert_eq!(htlcs[0].htlc_id, i);
			} else {
				assert!(false);
			}
			SendEvent::from_event(events.remove(0))
		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_payment_claimable!(nodes[1], our_payment_hash, our_payment_secret, 100000);
	}
	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_value_in_flight() {
	//BOLT 2 Requirement: if the sum of total offered HTLCs would exceed the remote's max_htlc_value_in_flight_msat: MUST NOT add an HTLC.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_value = 100000;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 0);
	let max_in_flight = get_channel_value_stat!(nodes[0], nodes[1], chan.2).counterparty_max_htlc_value_in_flight_msat;

	send_payment(&nodes[0], &vec!(&nodes[1])[..], max_in_flight);

	let (mut route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], max_in_flight);
	// Manually create a route over our max in flight (which our router normally automatically
	// limits us to.
	route.paths[0].hops[0].fee_msat =  max_in_flight + 1;
	unwrap_send_err!(nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)
		), true, APIError::ChannelUnavailable { .. }, {});
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	send_payment(&nodes[0], &[&nodes[1]], max_in_flight);
}

// BOLT 2 Requirements for the Receiver when handling an update_add_htlc message.
#[test]
fn test_update_add_htlc_bolt2_receiver_check_amount_received_more_than_min() {
	//BOLT2 Requirement: receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat -> SHOULD fail the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let htlc_minimum_msat: u64;
	{
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let channel = chan_lock.channel_by_id.get(&chan.2).unwrap();
		htlc_minimum_msat = channel.context().get_holder_htlc_minimum_msat();
	}

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], htlc_minimum_msat);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = htlc_minimum_msat-1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote side tried to send less than our minimum HTLC value\. Lower limit: \(\d+\)\. Actual: \(\d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_sender_can_afford_amount_sent() {
	//BOLT2 Requirement: receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw (while maintaining its channel reserve): SHOULD fail the channel
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);
	// The 2* and +1 are for the fee spike reserve.
	let commit_tx_fee_outbound = 2 * commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);

	let max_can_send = 5000000 - channel_reserve - commit_tx_fee_outbound;
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], max_can_send);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// Even though channel-initiator senders are required to respect the fee_spike_reserve,
	// at this time channel-initiatee receivers are not required to enforce that senders
	// respect the fee_spike_reserve.
	updates.update_add_htlcs[0].amount_msat = max_can_send + commit_tx_fee_outbound + 1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data, "Remote HTLC add would put them under remote reserve value");
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_htlc_limit() {
	//BOLT 2 Requirement: if a sending node adds more than its max_accepted_htlcs HTLCs to its local commitment transaction: SHOULD fail the channel
	//BOLT 2 Requirement: MUST allow multiple HTLCs with the same payment_hash.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	let send_amt = 3999999;
	let (mut route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000);
	route.paths[0].hops[0].fee_msat = send_amt;
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
	let cur_height = nodes[0].node.best_block.read().unwrap().height + 1;
	let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::signing_only(), &route.paths[0], &session_priv).unwrap();
	let recipient_onion_fields = RecipientOnionFields::secret_only(our_payment_secret);
	let (onion_payloads, _htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(
		&route.paths[0], send_amt, &recipient_onion_fields, cur_height, &None).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &our_payment_hash).unwrap();

	let mut msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 0,
		amount_msat: 1000,
		payment_hash: our_payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet.clone(),
		skimmed_fee_msat: None,
		blinding_point: None,
	};

	for i in 0..50 {
		msg.htlc_id = i as u64;
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);
	}
	msg.htlc_id = (50) as u64;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to push more than our max accepted HTLCs \(\d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_in_flight_msat() {
	//OR adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction: SHOULD fail the channel
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = get_channel_value_stat!(nodes[1], nodes[0], chan.2).counterparty_max_htlc_value_in_flight_msat + 1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new("Remote HTLC add would put them over our max HTLC value").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 1000000);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_cltv_expiry() {
	//BOLT2 Requirement: if sending node sets cltv_expiry to greater or equal to 500000000: SHOULD fail the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].cltv_expiry = 500000000;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data,"Remote provided CLTV expiry in seconds instead of block height");
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_repeated_id_ignore() {
	//BOLT 2 requirement: if the sender did not previously acknowledge the commitment of that HTLC: MUST ignore a repeated id value after a reconnection.
	// We test this by first testing that that repeated HTLCs pass commitment signature checks
	// after disconnect and that non-sequential htlc_ids result in a channel failure.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	//Disconnect and Reconnect
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	//Resend HTLC
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	assert_eq!(updates.commitment_signed.htlc_signatures.len(), 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let _bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote skipped HTLC ID \(skipped ID: \d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fulfill_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();

	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	let update_msg = msgs::UpdateFulfillHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		payment_preimage: our_payment_preimage,
	};

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	let update_msg = msgs::UpdateFailHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		reason: msgs::OnionErrorPacket { data: Vec::new()},
	};

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_malformed_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	let update_msg = msgs::UpdateFailMalformedHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		sha256_of_onion: [1; 32],
		failure_code: 0x8000,
	};

	nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_incorrect_htlc_id() {
	//BOLT 2 Requirement: A receiving node:	if the id does not correspond to an HTLC in its current commitment transaction MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (our_payment_preimage, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 100_000);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut update_fulfill_msg: msgs::UpdateFulfillHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				update_fulfill_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};

	update_fulfill_msg.htlc_id = 1;

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Remote tried to fulfill/fail an HTLC we couldn't find");
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_wrong_preimage() {
	//BOLT 2 Requirement: A receiving node:	if the payment_preimage value in update_fulfill_htlc doesn't SHA256 hash to the corresponding HTLC payment_hash	MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (our_payment_preimage, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 100_000);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut update_fulfill_msg: msgs::UpdateFulfillHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				update_fulfill_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};

	update_fulfill_msg.payment_preimage = PaymentPreimage([1; 32]);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill HTLC \(\d+\) with an incorrect preimage").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_missing_badonion_bit_for_malformed_htlc_message() {
	//BOLT 2 Requirement: A receiving node: if the BADONION bit in failure_code is not set for update_fail_malformed_htlc MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false, true);

	let events = nodes[1].node.get_and_clear_pending_msg_events();

	let mut update_msg: msgs::UpdateFailMalformedHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				assert!(update_fee.is_none());
				update_fail_malformed_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};
	update_msg.failure_code &= !0x8000;
	nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Got update_fail_malformed_htlc with BADONION not set");
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: err_msg.data }, [nodes[1].node.get_our_node_id()], 1000000);
}

#[test]
fn test_update_fulfill_htlc_bolt2_after_malformed_htlc_message_must_forward_update_fail_htlc() {
	//BOLT 2 Requirement: a receiving node which has an outgoing HTLC canceled by update_fail_malformed_htlc:
	//    * MUST return an error in the update_fail_htlc sent to the link which originally sent the HTLC, using the failure_code given and setting the data to sha256_of_onion.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1000000, 1000000);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100000);

	//First hop
	let mut payment_event = {
		nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	check_added_monitors!(nodes[1], 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	//Second Hop
	payment_event.msgs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[2], 0);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event.commitment_msg, false, true);

	let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let update_msg : (msgs::UpdateFailMalformedHTLC, msgs::CommitmentSigned) = {
		match events_3[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				assert!(update_fee.is_none());
				(update_fail_malformed_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};

	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), &update_msg.0);

	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[2], update_msg.1, false, true);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);

	//Confirm that handlinge the update_malformed_htlc message produces an update_fail_htlc message to be forwarded back along the route
	match events_4[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
		},
		_ => panic!("Unexpected event"),
	};

	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_channel_failed_after_message_with_badonion_node_perm_bits_set() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// First hop
	let mut payment_event = {
		nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		SendEvent::from_node(&nodes[0])
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	payment_event = SendEvent::from_node(&nodes[1]);
	assert_eq!(payment_event.msgs.len(), 1);

	// Second Hop
	payment_event.msgs[0].onion_routing_packet.version = 1; // Trigger an invalid_onion_version error
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[2], 0);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event.commitment_msg, false, true);

	let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			let mut update_msg = updates.update_fail_malformed_htlcs[0].clone();
			// Set the NODE bit (BADONION and PERM already set in invalid_onion_version error)
			update_msg.failure_code |= 0x2000;

			nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), &update_msg);
			commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true);
		},
		_ => panic!("Unexpected event"),
	}

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1],
		vec![HTLCDestination::NextHopChannel {
			node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);
	check_added_monitors!(nodes[1], 1);

	match events_4[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false, true);
		},
		_ => panic!("Unexpected event"),
	}

	let events_5 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 2);

	// Expect a PaymentPathFailed event with a ChannelFailure network update for the channel between
	// the node originating the error to its next hop.
	match events_5[0] {
		Event::PaymentPathFailed { error_code, failure: PathFailure::OnPath { network_update: Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent }) }, ..
		} => {
			assert_eq!(short_channel_id, chan_2.0.contents.short_channel_id);
			assert!(is_permanent);
			assert_eq!(error_code, Some(0x8000|0x4000|0x2000|4));
		},
		_ => panic!("Unexpected event"),
	}
	match events_5[1] {
		Event::PaymentFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, Some(our_payment_hash));
		},
		_ => panic!("Unexpected event"),
	}

	// TODO: Test actual removal of channel from NetworkGraph when it's implemented.
}

fn do_test_failure_delay_dust_htlc_local_commitment(announce_latest: bool) {
	// Dust-HTLC failure updates must be delayed until failure-trigger tx (in this case local commitment) reach ANTI_REORG_DELAY
	// We can have at most two valid local commitment tx, so both cases must be covered, and both txs must be checked to get them all as
	// HTLC could have been removed from lastest local commitment tx but still valid until we get remote RAA

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan =create_announced_chan_between_nodes(&nodes, 0, 1);

	let bs_dust_limit = nodes[1].node.per_peer_state.read().unwrap().get(&nodes[0].node.get_our_node_id())
		.unwrap().lock().unwrap().channel_by_id.get(&chan.2).unwrap().context().holder_dust_limit_satoshis;

	// We route 2 dust-HTLCs between A and B
	let (_, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Cache one local commitment tx as previous
	let as_prev_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	// Fail one HTLC to prune it in the will-be-latest-local commitment tx
	nodes[1].node.fail_htlc_backwards(&payment_hash_2);
	check_added_monitors!(nodes[1], 0);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash_2 }]);
	check_added_monitors!(nodes[1], 1);

	let remove = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &remove.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &remove.commitment_signed);
	check_added_monitors!(nodes[0], 1);

	// Cache one local commitment tx as lastest
	let as_last_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::SendRevokeAndACK { node_id, .. } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::UpdateHTLCs { node_id, .. } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	assert_ne!(as_prev_commitment_tx, as_last_commitment_tx);
	// Fail the 2 dust-HTLCs, move their failure in maturation buffer (htlc_updated_waiting_threshold_conf)
	if announce_latest {
		mine_transaction(&nodes[0], &as_last_commitment_tx[0]);
	} else {
		mine_transaction(&nodes[0], &as_prev_commitment_tx[0]);
	}

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);

	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	// Only 2 PaymentPathFailed events should show up, over-dust HTLC has to be failed by timeout tx
	assert_eq!(events.len(), 4);
	let mut first_failed = false;
	for event in events {
		match event {
			Event::PaymentPathFailed { payment_hash, .. } => {
				if payment_hash == payment_hash_1 {
					assert!(!first_failed);
					first_failed = true;
				} else {
					assert_eq!(payment_hash, payment_hash_2);
				}
			},
			Event::PaymentFailed { .. } => {}
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_failure_delay_dust_htlc_local_commitment() {
	do_test_failure_delay_dust_htlc_local_commitment(true);
	do_test_failure_delay_dust_htlc_local_commitment(false);
}

fn do_test_sweep_outbound_htlc_failure_update(revoked: bool, local: bool) {
	// Outbound HTLC-failure updates must be cancelled if we get a reorg before we reach ANTI_REORG_DELAY.
	// Broadcast of revoked remote commitment tx, trigger failure-update of dust/non-dust HTLCs
	// Broadcast of remote commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of timeout tx on remote commitment tx, trigger failure-udate of non-dust HTLCs
	// Broadcast of local commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of HTLC-timeout tx on local commitment tx, trigger failure-update of non-dust HTLCs

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let bs_dust_limit = nodes[1].node.per_peer_state.read().unwrap().get(&nodes[0].node.get_our_node_id())
		.unwrap().lock().unwrap().channel_by_id.get(&chan.2).unwrap().context().holder_dust_limit_satoshis;

	let (_payment_preimage_1, dust_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_payment_preimage_2, non_dust_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);
	let bs_commitment_tx = get_local_commitment_txn!(nodes[1], chan.2);

	// We revoked bs_commitment_tx
	if revoked {
		let (payment_preimage_3, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);
	}

	let mut timeout_tx = Vec::new();
	if local {
		// We fail dust-HTLC 1 by broadcast of local commitment tx
		mine_transaction(&nodes[0], &as_commitment_tx[0]);
		check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[0], dust_hash, false);

		connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS - ANTI_REORG_DELAY);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		// We fail non-dust-HTLC 2 by broadcast of local HTLC-timeout tx on local commitment tx
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		mine_transaction(&nodes[0], &timeout_tx[0]);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[0], non_dust_hash, false);
	} else {
		// We fail dust-HTLC 1 by broadcast of remote commitment tx. If revoked, fail also non-dust HTLC
		mine_transaction(&nodes[0], &bs_commitment_tx[0]);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);

		connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
		timeout_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().drain(..)
			.filter(|tx| tx.input[0].previous_output.txid == bs_commitment_tx[0].compute_txid()).collect();
		check_spends!(timeout_tx[0], bs_commitment_tx[0]);
		// For both a revoked or non-revoked commitment transaction, after ANTI_REORG_DELAY the
		// dust HTLC should have been failed.
		expect_payment_failed!(nodes[0], dust_hash, false);

		if !revoked {
			assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		} else {
			assert_eq!(timeout_tx[0].lock_time.to_consensus_u32(), 11);
		}
		// We fail non-dust-HTLC 2 by broadcast of local timeout/revocation-claim tx
		mine_transaction(&nodes[0], &timeout_tx[0]);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[0], non_dust_hash, false);
	}
}

#[test]
fn test_sweep_outbound_htlc_failure_update() {
	do_test_sweep_outbound_htlc_failure_update(false, true);
	do_test_sweep_outbound_htlc_failure_update(false, false);
	do_test_sweep_outbound_htlc_failure_update(true, false);
}

#[test]
fn test_user_configurable_csv_delay() {
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
	let logger = TestLogger::new();

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in OutboundV1Channel::new()
	if let Err(error) = OutboundV1Channel::new(&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), &nodes[1].node.init_features(), 1000000, 1000000, 0,
		&low_our_to_self_config, 0, 42, None, &logger)
	{
		match error {
			APIError::APIMisuseError { err } => { assert!(regex::Regex::new(r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks").unwrap().is_match(err.as_str())); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false) }

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in InboundV1Channel::new()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.common_fields.to_self_delay = 200;
	if let Err(error) = InboundV1Channel::new(&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), &nodes[0].node.channel_type_features(), &nodes[1].node.init_features(), &open_channel, 0,
		&low_our_to_self_config, 0, &nodes[0].logger, /*is_0conf=*/false)
	{
		match error {
			ChannelError::Close((err, _)) => {
				let regex = regex::Regex::new(r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks").unwrap();
				assert!(regex.is_match(err.as_str()));
			},
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Chanel::accept_channel()
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1000000, 1000000, 42, None, None).unwrap();
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id()));
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	accept_channel.common_fields.to_self_delay = 200;
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);
	let reason_msg;
	if let MessageSendEvent::HandleError { ref action, .. } = nodes[0].node.get_and_clear_pending_msg_events()[0] {
		match action {
			&ErrorAction::SendErrorMessage { ref msg } => {
				assert!(regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap().is_match(msg.data.as_str()));
				reason_msg = msg.data.clone();
			},
			_ => { panic!(); }
		}
	} else { panic!(); }
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: reason_msg }, [nodes[1].node.get_our_node_id()], 1000000);

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in InboundV1Channel::new()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.common_fields.to_self_delay = 200;
	if let Err(error) = InboundV1Channel::new(&LowerBoundedFeeEstimator::new(&test_utils::TestFeeEstimator::new(253)),
		&nodes[0].keys_manager, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), &nodes[0].node.channel_type_features(), &nodes[1].node.init_features(), &open_channel, 0,
		&high_their_to_self_config, 0, &nodes[0].logger, /*is_0conf=*/false)
	{
		match error {
			ChannelError::Close((err, _)) => {
				let regex = regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap();
				assert!(regex.is_match(err.as_str()));
			},
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }
}

#[test]
fn test_check_htlc_underpaying() {
	// Send payment through A -> B but A is maliciously
	// sending a probe payment (i.e less than expected value0
	// to B, B should refuse payment.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features()).unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 10_000);
	let route = get_route(&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph.read_only(),
		None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes).unwrap();
	let (_, our_payment_hash, _) = get_payment_preimage_hash!(nodes[0]);
	let our_payment_secret = nodes[1].node.create_inbound_payment_for_hash(our_payment_hash, Some(100_000), 7200, None).unwrap();
	nodes[0].node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	// Note that we first have to wait a random delay before processing the receipt of the HTLC,
	// and then will wait a second random delay before failing the HTLC back:
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);

	// Node 3 is expecting payment of 100_000 but received 10_000,
	// it should fail htlc like we didn't know the preimage.
	nodes[1].node.process_pending_htlc_forwards();

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fail_htlc, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_fail_htlcs[0].clone(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlc);
	commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

	// 10_000 msat as u64, followed by a height of CHAN_CONFIRM_DEPTH as u32
	let mut expected_failure_data = (10_000 as u64).to_be_bytes().to_vec();
	expected_failure_data.extend_from_slice(&CHAN_CONFIRM_DEPTH.to_be_bytes());
	expect_payment_failed!(nodes[0], our_payment_hash, true, 0x4000|15, &expected_failure_data[..]);
}

#[test]
fn test_announce_disable_channels() {
	// Create 2 channels between A and B. Disconnect B. Call timer_tick_occurred and check for generated
	// ChannelUpdate. Reconnect B, reestablish and check there is non-generated ChannelUpdate.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Connect a dummy node for proper future events broadcasting
	connect_dummy_node(&nodes[0]);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 0);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// Disconnect peers
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	for _ in 0..DISABLE_GOSSIP_TICKS + 1 {
		nodes[0].node.timer_tick_occurred();
	}
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	let mut chans_disabled = new_hash_map();
	for e in msg_events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.channel_flags & (1<<1), 1<<1); // The "channel disabled" bit should be set
				// Check that each channel gets updated exactly once
				if chans_disabled.insert(msg.contents.short_channel_id, msg.contents.timestamp).is_some() {
					panic!("Generated ChannelUpdate for wrong chan!");
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	// Reconnect peers
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 3);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 3);

	// Reestablish chan_1
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_2
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[1]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[1]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_3
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[2]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[2]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	for _ in 0..ENABLE_GOSSIP_TICKS {
		nodes[0].node.timer_tick_occurred();
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.timer_tick_occurred();
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	for e in msg_events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.channel_flags & (1<<1), 0); // The "channel disabled" bit should be off
				match chans_disabled.remove(&msg.contents.short_channel_id) {
					// Each update should have a higher timestamp than the previous one, replacing
					// the old one.
					Some(prev_timestamp) => assert!(msg.contents.timestamp > prev_timestamp),
					None => panic!("Generated ChannelUpdate for wrong chan!"),
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	// Check that each channel gets updated exactly once
	assert!(chans_disabled.is_empty());
}

#[test]
fn test_bump_penalty_txn_on_revoked_commitment() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on revoked commitment transaction before timelocks expiration

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let payment_params = PaymentParameters::from_node_id(nodes[0].node.get_our_node_id(), 30)
		.with_bolt11_features(nodes[0].node.bolt11_invoice_features()).unwrap();
	let (route,_, _, _) = get_route_and_payment_hash!(nodes[1], nodes[0], payment_params, 3000000);
	send_along_route(&nodes[1], route, &vec!(&nodes[0])[..], 3000000);

	let revoked_txn = get_local_commitment_txn!(nodes[0], chan.2);
	// Revoked commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
	assert_eq!(revoked_txn[0].output.len(), 4);
	assert_eq!(revoked_txn[0].input.len(), 1);
	assert_eq!(revoked_txn[0].input[0].previous_output.txid, chan.3.compute_txid());
	let revoked_txid = revoked_txn[0].compute_txid();

	let mut penalty_sum = 0;
	for outp in revoked_txn[0].output.iter() {
		if outp.script_pubkey.is_p2wsh() {
			penalty_sum += outp.value.to_sat();
		}
	}

	// Connect blocks to change height_timer range to see if we use right soonest_timelock
	let header_114 = connect_blocks(&nodes[1], 14);

	// Actually revoke tx by claiming a HTLC
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);
	connect_block(&nodes[1], &create_dummy_block(header_114, 42, vec![revoked_txn[0].clone()]));
	check_added_monitors!(nodes[1], 1);

	// One or more justice tx should have been broadcast, check it
	let penalty_1;
	let feerate_1;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1); // justice tx (broadcasted from ChannelMonitor)
		assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
		assert_eq!(node_txn[0].output.len(), 1);
		check_spends!(node_txn[0], revoked_txn[0]);
		let fee_1 = penalty_sum - node_txn[0].output[0].value.to_sat();
		feerate_1 = fee_1 * 1000 / node_txn[0].weight().to_wu();
		penalty_1 = node_txn[0].compute_txid();
		node_txn.clear();
	};

	// After exhaustion of height timer, a new bumped justice tx should have been broadcast, check it
	connect_blocks(&nodes[1], 15);
	let mut penalty_2 = penalty_1;
	let mut feerate_2 = 0;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		if node_txn[0].input[0].previous_output.txid == revoked_txid {
			assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
			assert_eq!(node_txn[0].output.len(), 1);
			check_spends!(node_txn[0], revoked_txn[0]);
			penalty_2 = node_txn[0].compute_txid();
			// Verify new bumped tx is different from last claiming transaction, we don't want spurrious rebroadcast
			assert_ne!(penalty_2, penalty_1);
			let fee_2 = penalty_sum - node_txn[0].output[0].value.to_sat();
			feerate_2 = fee_2 * 1000 / node_txn[0].weight().to_wu();
			// Verify 25% bump heuristic
			assert!(feerate_2 * 100 >= feerate_1 * 125);
			node_txn.clear();
		}
	}
	assert_ne!(feerate_2, 0);

	// After exhaustion of height timer for a 2nd time, a new bumped justice tx should have been broadcast, check it
	connect_blocks(&nodes[1], 1);
	let penalty_3;
	let mut feerate_3 = 0;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		if node_txn[0].input[0].previous_output.txid == revoked_txid {
			assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
			assert_eq!(node_txn[0].output.len(), 1);
			check_spends!(node_txn[0], revoked_txn[0]);
			penalty_3 = node_txn[0].compute_txid();
			// Verify new bumped tx is different from last claiming transaction, we don't want spurrious rebroadcast
			assert_ne!(penalty_3, penalty_2);
			let fee_3 = penalty_sum - node_txn[0].output[0].value.to_sat();
			feerate_3 = fee_3 * 1000 / node_txn[0].weight().to_wu();
			// Verify 25% bump heuristic
			assert!(feerate_3 * 100 >= feerate_2 * 125);
			node_txn.clear();
		}
	}
	assert_ne!(feerate_3, 0);

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_bump_penalty_txn_on_revoked_htlcs() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to sure
	// we're able to claim outputs on revoked HTLC transactions before timelocks expiration

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	// Lock HTLC in both directions (using a slightly lower CLTV delay to provide timely RBF bumps)
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), 50).with_bolt11_features(nodes[1].node.bolt11_invoice_features()).unwrap();
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 3_000_000);
	let route = get_route(&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph.read_only(), None,
		nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes).unwrap();
	let payment_preimage = send_along_route(&nodes[0], route, &[&nodes[1]], 3_000_000).0;
	let payment_params = PaymentParameters::from_node_id(nodes[0].node.get_our_node_id(), 50)
		.with_bolt11_features(nodes[0].node.bolt11_invoice_features()).unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 3_000_000);
	let route = get_route(&nodes[1].node.get_our_node_id(), &route_params, &nodes[1].network_graph.read_only(), None,
		nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes).unwrap();
	let failed_payment_hash = send_along_route(&nodes[1], route, &[&nodes[0]], 3_000_000).1;

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	// B will generate both revoked HTLC-timeout/HTLC-preimage txn from revoked commitment tx
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![revoked_local_txn[0].clone()]));
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	connect_blocks(&nodes[1], 50); // Confirm blocks until the HTLC expires (note CLTV was explicitly 50 above)

	let revoked_htlc_txn = {
		let txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);

		assert_eq!(txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(txn[0].input.len(), 1);
		check_spends!(txn[0], revoked_local_txn[0]);

		assert_eq!(txn[1].input.len(), 1);
		assert_eq!(txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(txn[1].output.len(), 1);
		check_spends!(txn[1], revoked_local_txn[0]);

		txn
	};

	// Broadcast set of revoked txn on A
	let hash_128 = connect_blocks(&nodes[0], 40);
	let block_11 = create_dummy_block(hash_128, 42, vec![revoked_local_txn[0].clone()]);
	connect_block(&nodes[0], &block_11);
	let block_129 = create_dummy_block(block_11.block_hash(), 42, vec![revoked_htlc_txn[0].clone(), revoked_htlc_txn[1].clone()]);
	connect_block(&nodes[0], &block_129);
	let events = nodes[0].node.get_and_clear_pending_events();
	expect_pending_htlcs_forwardable_conditions(events[0..2].to_vec(), &[HTLCDestination::FailedPayment { payment_hash: failed_payment_hash }]);
	match events.last().unwrap() {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
		_ => panic!("Unexpected event"),
	}
	let first;
	let feerate_1;
	let penalty_txn;
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 4); // 3 penalty txn on revoked commitment tx + 1 penalty tnx on revoked HTLC txn
		// Verify claim tx are spending revoked HTLC txn

		// node_txn 0-2 each spend a separate revoked output from revoked_local_txn[0]
		// Note that node_txn[0] and node_txn[1] are bogus - they double spend the revoked_htlc_txn
		// which are included in the same block (they are broadcasted because we scan the
		// transactions linearly and generate claims as we go, they likely should be removed in the
		// future).
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[0], revoked_local_txn[0]);
		assert_eq!(node_txn[1].input.len(), 1);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		assert_eq!(node_txn[2].input.len(), 1);
		check_spends!(node_txn[2], revoked_local_txn[0]);

		// Each of the three justice transactions claim a separate (single) output of the three
		// available, which we check here:
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[2].input[0].previous_output);
		assert_ne!(node_txn[1].input[0].previous_output, node_txn[2].input[0].previous_output);

		assert_eq!(node_txn[0].input[0].previous_output, revoked_htlc_txn[1].input[0].previous_output);
		assert_eq!(node_txn[1].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);

		// node_txn[3] spends the revoked outputs from the revoked_htlc_txn (which only have one
		// output, checked above).
		assert_eq!(node_txn[3].input.len(), 2);
		assert_eq!(node_txn[3].output.len(), 1);
		check_spends!(node_txn[3], revoked_htlc_txn[0], revoked_htlc_txn[1]);

		first = node_txn[3].compute_txid();
		// Store both feerates for later comparison
		let fee_1 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value - node_txn[3].output[0].value;
		feerate_1 = fee_1 * 1000 / node_txn[3].weight().to_wu();
		penalty_txn = vec![node_txn[2].clone()];
		node_txn.clear();
	}

	// Connect one more block to see if bumped penalty are issued for HTLC txn
	let block_130 = create_dummy_block(block_129.block_hash(), 42, penalty_txn);
	connect_block(&nodes[0], &block_130);
	let block_131 = create_dummy_block(block_130.block_hash(), 42, Vec::new());
	connect_block(&nodes[0], &block_131);

	// Few more blocks to confirm penalty txn
	connect_blocks(&nodes[0], 4);
	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	let header_144 = connect_blocks(&nodes[0], 9);
	let node_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		assert_eq!(node_txn[0].input.len(), 2);
		check_spends!(node_txn[0], revoked_htlc_txn[0], revoked_htlc_txn[1]);
		// Verify bumped tx is different and 25% bump heuristic
		assert_ne!(first, node_txn[0].compute_txid());
		let fee_2 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value - node_txn[0].output[0].value;
		let feerate_2 = fee_2 * 1000 / node_txn[0].weight().to_wu();
		assert!(feerate_2 * 100 > feerate_1 * 125);
		let txn = vec![node_txn[0].clone()];
		node_txn.clear();
		txn
	};
	// Broadcast claim txn and confirm blocks to avoid further bumps on this outputs
	connect_block(&nodes[0], &create_dummy_block(header_144, 42, node_txn));
	connect_blocks(&nodes[0], 20);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// We verify than no new transaction has been broadcast because previously
		// we were buggy on this exact behavior by not tracking for monitoring remote HTLC outputs (see #411)
		// which means we wouldn't see a spend of them by a justice tx and bumped justice tx
		// were generated forever instead of safe cleaning after confirmation and ANTI_REORG_SAFE_DELAY blocks.
		// Enforce spending of revoked htlc output by claiming transaction remove request as expected and dry
		// up bumped justice generation.
		assert_eq!(node_txn.len(), 0);
		node_txn.clear();
	}
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_bump_penalty_txn_on_remote_commitment() {
	// In case of claim txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on remote commitment transaction before timelocks expiration

	// Create 2 HTLCs
	// Provide preimage for one
	// Check aggregation

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000).0;

	// Remote commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
	let remote_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(remote_txn[0].output.len(), 4);
	assert_eq!(remote_txn[0].input.len(), 1);
	assert_eq!(remote_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Claim a HTLC without revocation (provide B monitor with preimage)
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);
	mine_transaction(&nodes[1], &remote_txn[0]);
	check_added_monitors!(nodes[1], 2);
	connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	// One or more claim tx should have been broadcast, check it
	let timeout;
	let preimage;
	let preimage_bump;
	let feerate_timeout;
	let feerate_preimage;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// 3 transactions including:
		//   preimage and timeout sweeps from remote commitment + preimage sweep bump
		assert_eq!(node_txn.len(), 3);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(node_txn[1], remote_txn[0]);
		check_spends!(node_txn[2], remote_txn[0]);

		preimage = node_txn[0].compute_txid();
		let index = node_txn[0].input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat() - node_txn[0].output[0].value.to_sat();
		feerate_preimage = fee * 1000 / node_txn[0].weight().to_wu();

		let (preimage_bump_tx, timeout_tx) = if node_txn[2].input[0].previous_output == node_txn[0].input[0].previous_output {
			(node_txn[2].clone(), node_txn[1].clone())
		} else {
			(node_txn[1].clone(), node_txn[2].clone())
		};

		preimage_bump = preimage_bump_tx;
		check_spends!(preimage_bump, remote_txn[0]);
		assert_eq!(node_txn[0].input[0].previous_output, preimage_bump.input[0].previous_output);

		timeout = timeout_tx.compute_txid();
		let index = timeout_tx.input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat() - timeout_tx.output[0].value.to_sat();
		feerate_timeout = fee * 1000 / timeout_tx.weight().to_wu();

		node_txn.clear();
	};
	assert_ne!(feerate_timeout, 0);
	assert_ne!(feerate_preimage, 0);

	// After exhaustion of height timer, new bumped claim txn should have been broadcast, check it
	connect_blocks(&nodes[1], 1);
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(preimage_bump.input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(preimage_bump, remote_txn[0]);

		let index = preimage_bump.input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat() - preimage_bump.output[0].value.to_sat();
		let new_feerate = fee * 1000 / preimage_bump.weight().to_wu();
		assert!(new_feerate * 100 > feerate_timeout * 125);
		assert_ne!(timeout, preimage_bump.compute_txid());

		let index = node_txn[0].input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat() - node_txn[0].output[0].value.to_sat();
		let new_feerate = fee * 1000 / node_txn[0].weight().to_wu();
		assert!(new_feerate * 100 > feerate_preimage * 125);
		assert_ne!(preimage, node_txn[0].compute_txid());

		node_txn.clear();
	}

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_counterparty_raa_skip_no_crash() {
	// Previously, if our counterparty sent two RAAs in a row without us having provided a
	// commitment transaction, we would have happily carried on and provided them the next
	// commitment transaction based on one RAA forward. This would probably eventually have led to
	// channel closure, but it would not have resulted in funds loss. Still, our
	// TestChannelSigner would have panicked as it doesn't like jumps into the future. Here, we
	// check simply that the channel is closed in response to such an RAA, but don't check whether
	// we decide to punish our counterparty for revoking their funds (as we don't currently
	// implement that).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let per_commitment_secret;
	let next_per_commitment_point;
	{
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let mut guard = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let keys = guard.channel_by_id.get_mut(&channel_id).map(
			|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
		).flatten().unwrap().get_signer();

		const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

		// Make signer believe we got a counterparty signature, so that it allows the revocation
		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		per_commitment_secret = keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER).unwrap();

		// Must revoke without gaps
		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 1).unwrap();

		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		next_per_commitment_point = PublicKey::from_secret_key(&Secp256k1::new(),
			&SecretKey::from_slice(&keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 2).unwrap()).unwrap());
	}

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(),
		&msgs::RevokeAndACK {
			channel_id,
			per_commitment_secret,
			next_per_commitment_point,
			#[cfg(taproot)]
			next_local_nonce: None,
		});
	assert_eq!(check_closed_broadcast!(nodes[1], true).unwrap().data, "Received an unexpected revoke_and_ack");
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: "Received an unexpected revoke_and_ack".to_string() }
		, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_bump_txn_sanitize_tracking_maps() {
	// Sanitizing pendning_claim_request and claimable_outpoints used to be buggy,
	// verify we clean then right after expiration of ANTI_REORG_DELAY.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	// Lock HTLC in both directions
	let (payment_preimage_1, ..) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000);
	let (_, payment_hash_2, ..) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 9_000_000);

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

	// Broadcast set of revoked txn on A
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + 2 - CHAN_CONFIRM_DEPTH);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[0], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash_2 }]);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);

	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);
	let penalty_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3); //ChannelMonitor: justice txn * 3
		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		check_spends!(node_txn[2], revoked_local_txn[0]);
		let penalty_txn = vec![node_txn[0].clone(), node_txn[1].clone(), node_txn[2].clone()];
		node_txn.clear();
		penalty_txn
	};
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, penalty_txn));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	{
		let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(OutPoint { txid: chan.3.compute_txid(), index: 0 }).unwrap();
		assert!(monitor.inner.lock().unwrap().onchain_tx_handler.pending_claim_requests.is_empty());
		assert!(monitor.inner.lock().unwrap().onchain_tx_handler.claimable_outpoints.is_empty());
	}
}

#[test]
fn test_channel_conf_timeout() {
	// Tests that, for inbound channels, we give up on them if the funding transaction does not
	// confirm within 2016 blocks, as recommended by BOLT 2.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let _funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 100_000);

	// The outbound node should wait forever for confirmation:
	// This matches `channel::FUNDING_CONF_DEADLINE_BLOCKS` and BOLT 2's suggested timeout, thus is
	// copied here instead of directly referencing the constant.
	connect_blocks(&nodes[0], 2016);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// The inbound node should fail the channel after exactly 2016 blocks
	connect_blocks(&nodes[1], 2015);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[1], 1);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::FundingTimedOut, [nodes[0].node.get_our_node_id()], 1000000);
	let close_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(close_ev.len(), 1);
	match close_ev[0] {
		MessageSendEvent::HandleError { action: ErrorAction::DisconnectPeer { ref msg }, ref node_id } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert_eq!(msg.as_ref().unwrap().data, "Channel closed because funding transaction failed to confirm within 2016 blocks");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_override_channel_config() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Node0 initiates a channel to node1 using the override config.
	let mut override_config = UserConfig::default();
	override_config.channel_handshake_config.our_to_self_delay = 200;

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 16_000_000, 12_000_000, 42, None, Some(override_config)).unwrap();

	// Assert the channel created by node0 is using the override config.
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(res.common_fields.channel_flags, 0);
	assert_eq!(res.common_fields.to_self_delay, 200);
}

#[test]
fn test_override_0msat_htlc_minimum() {
	let mut zero_config = UserConfig::default();
	zero_config.channel_handshake_config.our_htlc_minimum_msat = 0;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(zero_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 16_000_000, 12_000_000, 42, None, Some(zero_config)).unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(res.common_fields.htlc_minimum_msat, 1);

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &res);
	let res = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	assert_eq!(res.common_fields.htlc_minimum_msat, 1);
}

#[test]
fn test_channel_update_has_correct_htlc_maximum_msat() {
	// Tests that the `ChannelUpdate` message has the correct values for `htlc_maximum_msat` set.
	// Bolt 7 specifies that if present `htlc_maximum_msat`:
	// 1. MUST be set to less than or equal to the channel capacity. In LDK, this is capped to
	// 90% of the `channel_value`.
	// 2. MUST be set to less than or equal to the `max_htlc_value_in_flight_msat` received from the peer.

	let mut config_30_percent = UserConfig::default();
	config_30_percent.channel_handshake_config.announce_for_forwarding = true;
	config_30_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 30;
	let mut config_50_percent = UserConfig::default();
	config_50_percent.channel_handshake_config.announce_for_forwarding = true;
	config_50_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 50;
	let mut config_95_percent = UserConfig::default();
	config_95_percent.channel_handshake_config.announce_for_forwarding = true;
	config_95_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 95;
	let mut config_100_percent = UserConfig::default();
	config_100_percent.channel_handshake_config.announce_for_forwarding = true;
	config_100_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;

	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[Some(config_30_percent), Some(config_50_percent), Some(config_95_percent), Some(config_100_percent)]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let channel_value_satoshis = 100000;
	let channel_value_msat = channel_value_satoshis * 1000;
	let channel_value_30_percent_msat = (channel_value_msat as f64 * 0.3) as u64;
	let channel_value_50_percent_msat = (channel_value_msat as f64 * 0.5) as u64;
	let channel_value_90_percent_msat = (channel_value_msat as f64 * 0.9) as u64;

	let (node_0_chan_update, node_1_chan_update, _, _)  = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value_satoshis, 10001);
	let (node_2_chan_update, node_3_chan_update, _, _)  = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, channel_value_satoshis, 10001);

	// Assert that `node[0]`'s `ChannelUpdate` is capped at 50 percent of the `channel_value`, as
	// that's the value of `node[1]`'s `holder_max_htlc_value_in_flight_msat`.
	assert_eq!(node_0_chan_update.contents.htlc_maximum_msat, channel_value_50_percent_msat);
	// Assert that `node[1]`'s `ChannelUpdate` is capped at 30 percent of the `channel_value`, as
	// that's the value of `node[0]`'s `holder_max_htlc_value_in_flight_msat`.
	assert_eq!(node_1_chan_update.contents.htlc_maximum_msat, channel_value_30_percent_msat);

	// Assert that `node[2]`'s `ChannelUpdate` is capped at 90 percent of the `channel_value`, as
	// the value of `node[3]`'s `holder_max_htlc_value_in_flight_msat` (100%), exceeds 90% of the
	// `channel_value`.
	assert_eq!(node_2_chan_update.contents.htlc_maximum_msat, channel_value_90_percent_msat);
	// Assert that `node[3]`'s `ChannelUpdate` is capped at 90 percent of the `channel_value`, as
	// the value of `node[2]`'s `holder_max_htlc_value_in_flight_msat` (95%), exceeds 90% of the
	// `channel_value`.
	assert_eq!(node_3_chan_update.contents.htlc_maximum_msat, channel_value_90_percent_msat);
}

#[test]
fn test_manually_accept_inbound_channel_request() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, Some(manually_accept_conf)).unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// accepting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 23).unwrap();
		}
		_ => panic!("Unexpected event"),
	}

	let accept_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(accept_msg_ev.len(), 1);

	match accept_msg_ev[0] {
		MessageSendEvent::SendAcceptChannel { ref node_id, .. } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		}
		_ => panic!("Unexpected event"),
	}
	let error_message = "Channel force-closed";
	nodes[1].node.force_close_broadcasting_latest_txn(&temp_channel_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();

	let close_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(close_msg_ev.len(), 1);

	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::ChannelClosed { user_channel_id, .. } => {
			assert_eq!(user_channel_id, 23);
		}
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_manually_reject_inbound_channel_request() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, Some(manually_accept_conf)).unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// rejecting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	let error_message = "Channel force-closed";
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.force_close_broadcasting_latest_txn(&temporary_channel_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
		}
		_ => panic!("Unexpected event"),
	}

	let close_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(close_msg_ev.len(), 1);

	match close_msg_ev[0] {
		MessageSendEvent::HandleError { ref node_id, .. } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		}
		_ => panic!("Unexpected event"),
	}

	// There should be no more events to process, as the channel was never opened.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn test_can_not_accept_inbound_channel_twice() {
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, Some(manually_accept_conf)).unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &res);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in `msg_events` before
	// accepting the inbound channel request.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 0).unwrap();
			let api_res = nodes[1].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 0);
			match api_res {
				Err(APIError::APIMisuseError { err }) => {
					assert_eq!(err, "No such channel awaiting to be accepted.");
				},
				Ok(_) => panic!("Channel shouldn't be possible to be accepted twice"),
				Err(e) => panic!("Unexpected Error {:?}", e),
			}
		}
		_ => panic!("Unexpected event"),
	}

	// Ensure that the channel wasn't closed after attempting to accept it twice.
	let accept_msg_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(accept_msg_ev.len(), 1);

	match accept_msg_ev[0] {
		MessageSendEvent::SendAcceptChannel { ref node_id, .. } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		}
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_can_not_accept_unknown_inbound_channel() {
	let chanmon_cfg = create_chanmon_cfgs(2);
	let node_cfg = create_node_cfgs(2, &chanmon_cfg);
	let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
	let nodes = create_network(2, &node_cfg, &node_chanmgr);

	let unknown_channel_id = ChannelId::new_zero();
	let api_res = nodes[0].node.accept_inbound_channel(&unknown_channel_id, &nodes[1].node.get_our_node_id(), 0);
	match api_res {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(err, "No such channel awaiting to be accepted.");
		},
		Ok(_) => panic!("It shouldn't be possible to accept an unkown channel"),
		Err(e) => panic!("Unexpected Error: {:?}", e),
	}
}

#[test]
fn test_onion_value_mpp_set_calculation() {
	// Test that we use the onion value `amt_to_forward` when
	// calculating whether we've reached the `total_msat` of an MPP
	// by having a routing node forward more than `amt_to_forward`
	// and checking that the receiving node doesn't generate
	// a PaymentClaimable event too early
	let node_count = 4;
	let chanmon_cfgs = create_chanmon_cfgs(node_count);
	let node_cfgs = create_node_cfgs(node_count, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(node_count, &node_cfgs, &vec![None; node_count]);
	let mut nodes = create_network(node_count, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let total_msat = 100_000;
	let expected_paths: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let (mut route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[3], total_msat);
	let sample_path = route.paths.pop().unwrap();

	let mut path_1 = sample_path.clone();
	path_1.hops[0].pubkey = nodes[1].node.get_our_node_id();
	path_1.hops[0].short_channel_id = chan_1_id;
	path_1.hops[1].pubkey = nodes[3].node.get_our_node_id();
	path_1.hops[1].short_channel_id = chan_3_id;
	path_1.hops[1].fee_msat = 100_000;
	route.paths.push(path_1);

	let mut path_2 = sample_path.clone();
	path_2.hops[0].pubkey = nodes[2].node.get_our_node_id();
	path_2.hops[0].short_channel_id = chan_2_id;
	path_2.hops[1].pubkey = nodes[3].node.get_our_node_id();
	path_2.hops[1].short_channel_id = chan_4_id;
	path_2.hops[1].fee_msat = 1_000;
	route.paths.push(path_2);

	// Send payment
	let payment_id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	let onion_session_privs = nodes[0].node.test_add_new_pending_payment(our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), payment_id, &route).unwrap();
	nodes[0].node.test_send_payment_internal(&route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), None, payment_id, Some(total_msat), onion_session_privs).unwrap();
	check_added_monitors!(nodes[0], expected_paths.len());

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());

	// First path
	let ev = remove_first_msg_event_to_node(&expected_paths[0][0].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);
	let mut prev_node = &nodes[0];

	for (idx, &node) in expected_paths[0].iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		if idx == 0 { // routing node
			let session_priv = [3; 32];
			let height = nodes[0].best_block_info().1;
			let session_priv = SecretKey::from_slice(&session_priv).unwrap();
			let mut onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
			let recipient_onion_fields = RecipientOnionFields::secret_only(our_payment_secret);
			let (mut onion_payloads, _, _) = onion_utils::build_onion_payloads(&route.paths[0], 100_000,
				&recipient_onion_fields, height + 1, &None).unwrap();
			// Edit amt_to_forward to simulate the sender having set
			// the final amount and the routing node taking less fee
			if let msgs::OutboundOnionPayload::Receive {
				ref mut sender_intended_htlc_amt_msat, ..
			} = onion_payloads[1] {
				*sender_intended_htlc_amt_msat = 99_000;
			} else { panic!() }
			let new_onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &our_payment_hash).unwrap();
			payment_event.msgs[0].onion_routing_packet = new_onion_packet;
		}

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(node);

		if idx == 0 {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors!(node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		} else {
			let events_2 = node.node.get_and_clear_pending_events();
			assert!(events_2.is_empty());
		}

		prev_node = node;
	}

	// Second path
	let ev = remove_first_msg_event_to_node(&expected_paths[1][0].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_paths[1], 101_000, our_payment_hash.clone(), Some(our_payment_secret), ev, true, None);

	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_paths, our_payment_preimage)
	);
}

fn do_test_overshoot_mpp(msat_amounts: &[u64], total_msat: u64) {

	let routing_node_count = msat_amounts.len();
	let node_count = routing_node_count + 2;

	let chanmon_cfgs = create_chanmon_cfgs(node_count);
	let node_cfgs = create_node_cfgs(node_count, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(node_count, &node_cfgs, &vec![None; node_count]);
	let nodes = create_network(node_count, &node_cfgs, &node_chanmgrs);

	let src_idx = 0;
	let dst_idx = 1;

	// Create channels for each amount
	let mut expected_paths = Vec::with_capacity(routing_node_count);
	let mut src_chan_ids = Vec::with_capacity(routing_node_count);
	let mut dst_chan_ids = Vec::with_capacity(routing_node_count);
	for i in 0..routing_node_count {
		let routing_node = 2 + i;
		let src_chan_id = create_announced_chan_between_nodes(&nodes, src_idx, routing_node).0.contents.short_channel_id;
		src_chan_ids.push(src_chan_id);
		let dst_chan_id = create_announced_chan_between_nodes(&nodes, routing_node, dst_idx).0.contents.short_channel_id;
		dst_chan_ids.push(dst_chan_id);
		let path = vec![&nodes[routing_node], &nodes[dst_idx]];
		expected_paths.push(path);
	}
	let expected_paths: Vec<&[&Node]> = expected_paths.iter().map(|route| route.as_slice()).collect();

	// Create a route for each amount
	let example_amount = 100000;
	let (mut route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(&nodes[src_idx], nodes[dst_idx], example_amount);
	let sample_path = route.paths.pop().unwrap();
	for i in 0..routing_node_count {
		let routing_node = 2 + i;
		let mut path = sample_path.clone();
		path.hops[0].pubkey = nodes[routing_node].node.get_our_node_id();
		path.hops[0].short_channel_id = src_chan_ids[i];
		path.hops[1].pubkey = nodes[dst_idx].node.get_our_node_id();
		path.hops[1].short_channel_id = dst_chan_ids[i];
		path.hops[1].fee_msat = msat_amounts[i];
		route.paths.push(path);
	}

	// Send payment with manually set total_msat
	let payment_id = PaymentId(nodes[src_idx].keys_manager.backing.get_secure_random_bytes());
	let onion_session_privs = nodes[src_idx].node.test_add_new_pending_payment(our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), payment_id, &route).unwrap();
	nodes[src_idx].node.test_send_payment_internal(&route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), None, payment_id, Some(total_msat), onion_session_privs).unwrap();
	check_added_monitors!(nodes[src_idx], expected_paths.len());

	let mut events = nodes[src_idx].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());
	let mut amount_received = 0;
	for (path_idx, expected_path) in expected_paths.iter().enumerate() {
		let ev = remove_first_msg_event_to_node(&expected_path[0].node.get_our_node_id(), &mut events);

		let current_path_amount = msat_amounts[path_idx];
		amount_received += current_path_amount;
		let became_claimable_now = amount_received >= total_msat && amount_received - current_path_amount < total_msat;
		pass_along_path(&nodes[src_idx], expected_path, amount_received, our_payment_hash.clone(), Some(our_payment_secret), ev, became_claimable_now, None);
	}

	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[src_idx], &expected_paths, our_payment_preimage)
	);
}

#[test]
fn test_overshoot_mpp() {
	do_test_overshoot_mpp(&[100_000, 101_000], 200_000);
	do_test_overshoot_mpp(&[100_000, 10_000, 100_000], 200_000);
}

#[test]
fn test_simple_mpp() {
	// Simple test of sending a multi-path payment.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;
	route.paths[1].hops[0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1].hops[0].short_channel_id = chan_2_id;
	route.paths[1].hops[1].short_channel_id = chan_4_id;
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], 200_000, payment_hash, payment_secret);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], payment_preimage)
	);
}

#[test]
fn test_preimage_storage() {
	// Simple test of payment preimage storage allowing no client-side storage to claim payments
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;

	{
		let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(100_000), 7200, None).unwrap();
		let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
		nodes[0].node.send_payment_with_route(route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	}
	// Note that after leaving the above scope we have no knowledge of any arguments or return
	// values from previous calls.
	expect_pending_htlcs_forwardable!(nodes[1]);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { ref purpose, .. } => {
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment { payment_preimage, .. } => {
					claim_payment(&nodes[0], &[&nodes[1]], payment_preimage.unwrap());
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_bad_secret_hash() {
	// Simple test of unregistered payment hash/invalid payment secret handling
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;

	let random_payment_hash = PaymentHash([42; 32]);
	let random_payment_secret = PaymentSecret([43; 32]);
	let (our_payment_hash, our_payment_secret) = nodes[1].node.create_inbound_payment(Some(100_000), 2, None).unwrap();
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	// All the below cases should end up being handled exactly identically, so we macro the
	// resulting events.
	macro_rules! handle_unknown_invalid_payment_data {
		($payment_hash: expr) => {
			check_added_monitors!(nodes[0], 1);
			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			let payment_event = SendEvent::from_event(events.pop().unwrap());
			nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
			commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

			// We have to forward pending HTLCs once to process the receipt of the HTLC and then
			// again to process the pending backwards-failure of the HTLC
			expect_pending_htlcs_forwardable!(nodes[1]);
			expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment{ payment_hash: $payment_hash }]);
			check_added_monitors!(nodes[1], 1);

			// We should fail the payment back
			let mut events = nodes[1].node.get_and_clear_pending_msg_events();
			match events.pop().unwrap() {
				MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. } } => {
					nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
					commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false);
				},
				_ => panic!("Unexpected event"),
			}
		}
	}

	let expected_error_code = 0x4000|15; // incorrect_or_unknown_payment_details
	// Error data is the HTLC value (100,000) and current block height
	let expected_error_data = [0, 0, 0, 0, 0, 1, 0x86, 0xa0, 0, 0, 0, CHAN_CONFIRM_DEPTH as u8];

	// Send a payment with the right payment hash but the wrong payment secret
	nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash,
		RecipientOnionFields::secret_only(random_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	handle_unknown_invalid_payment_data!(our_payment_hash);
	expect_payment_failed!(nodes[0], our_payment_hash, true, expected_error_code, expected_error_data);

	// Send a payment with a random payment hash, but the right payment secret
	nodes[0].node.send_payment_with_route(route.clone(), random_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(random_payment_hash.0)).unwrap();
	handle_unknown_invalid_payment_data!(random_payment_hash);
	expect_payment_failed!(nodes[0], random_payment_hash, true, expected_error_code, expected_error_data);

	// Send a payment with a random payment hash and random payment secret
	nodes[0].node.send_payment_with_route(route, random_payment_hash,
		RecipientOnionFields::secret_only(random_payment_secret), PaymentId(random_payment_hash.0)).unwrap();
	handle_unknown_invalid_payment_data!(random_payment_hash);
	expect_payment_failed!(nodes[0], random_payment_hash, true, expected_error_code, expected_error_data);
}

#[test]
fn test_update_err_monitor_lockdown() {
	// Our monitor will lock update of local commitment transaction if a broadcastion condition
	// has been fulfilled (either force-close from Channel or block height requiring a HTLC-
	// timeout). Trying to update monitor after lockdown should return a ChannelMonitorUpdateStatus
	// error.
	//
	// This scenario may happen in a watchtower setup, where watchtower process a block height
	// triggering a timeout while a slow-block-processing ChannelManager receives a local signed
	// commitment at same time.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let outpoint = OutPoint { txid: chan_1.3.compute_txid(), index: 0 };

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);

	// Copy ChainMonitor to simulate a watchtower and update block height of node 0 until its ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let persister = test_utils::TestPersister::new();
	let watchtower = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(outpoint).unwrap();
			let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()), (nodes[0].keys_manager, nodes[0].keys_manager)).unwrap().1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &chanmon_cfgs[0].tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert_eq!(watchtower.watch_channel(outpoint, new_monitor), Ok(ChannelMonitorUpdateStatus::Completed));
		watchtower
	};
	let block = create_dummy_block(BlockHash::all_zeros(), 42, Vec::new());
	// Make the tx_broadcaster aware of enough blocks that it doesn't think we're violating
	// transaction lock time requirements here.
	chanmon_cfgs[0].tx_broadcaster.blocks.lock().unwrap().resize(200, (block.clone(), 200));
	watchtower.chain_monitor.block_connected(&block, 200);

	// Try to update ChannelMonitor
	nodes[1].node.claim_funds(preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 9_000_000);

	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	{
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		if let ChannelPhase::Funded(ref mut channel) = get_channel_ref!(nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_1.2) {
			if let Ok(Some(update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].logger) {
				assert_eq!(watchtower.chain_monitor.update_channel(outpoint, &update), ChannelMonitorUpdateStatus::InProgress);
				assert_eq!(nodes[0].chain_monitor.update_channel(outpoint, &update), ChannelMonitorUpdateStatus::Completed);
			} else { assert!(false); }
		} else {
			assert!(false);
		}
	}
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
}

#[test]
fn test_concurrent_monitor_claim() {
	// Watchtower A receives block, broadcasts state N, then channel receives new state N+1,
	// sending it to both watchtowers, Bob accepts N+1, then receives block and broadcasts
	// the latest state N+1, Alice rejects state N+1, but Bob has already broadcast it,
	// state N+1 confirms. Alice claims output from state N+1.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let outpoint = OutPoint { txid: chan_1.3.compute_txid(), index: 0 };

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;

	// Copy ChainMonitor to simulate watchtower Alice and update block height her ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", "Alice"));
	let persister = test_utils::TestPersister::new();
	let alice_broadcaster = test_utils::TestBroadcaster::with_blocks(
		Arc::new(Mutex::new(nodes[0].blocks.lock().unwrap().clone())),
	);
	let watchtower_alice = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(outpoint).unwrap();
			let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()), (nodes[0].keys_manager, nodes[0].keys_manager)).unwrap().1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &alice_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert_eq!(watchtower.watch_channel(outpoint, new_monitor), Ok(ChannelMonitorUpdateStatus::Completed));
		watchtower
	};
	let block = create_dummy_block(BlockHash::all_zeros(), 42, Vec::new());
	// Make Alice aware of enough blocks that it doesn't think we're violating transaction lock time
	// requirements here.
	const HTLC_TIMEOUT_BROADCAST: u32 = CHAN_CONFIRM_DEPTH + 1 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS;
	alice_broadcaster.blocks.lock().unwrap().resize((HTLC_TIMEOUT_BROADCAST) as usize, (block.clone(), HTLC_TIMEOUT_BROADCAST));
	watchtower_alice.chain_monitor.block_connected(&block, HTLC_TIMEOUT_BROADCAST);

	// Watchtower Alice should have broadcast a commitment/HTLC-timeout
	{
		let mut txn = alice_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 2);
		check_spends!(txn[0], chan_1.3);
		check_spends!(txn[1], txn[0]);
	};

	// Copy ChainMonitor to simulate watchtower Bob and make it receive a commitment update first.
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", "Bob"));
	let persister = test_utils::TestPersister::new();
	let bob_broadcaster = test_utils::TestBroadcaster::with_blocks(Arc::clone(&alice_broadcaster.blocks));
	let watchtower_bob = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(outpoint).unwrap();
			let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()), (nodes[0].keys_manager, nodes[0].keys_manager)).unwrap().1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &bob_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert_eq!(watchtower.watch_channel(outpoint, new_monitor), Ok(ChannelMonitorUpdateStatus::Completed));
		watchtower
	};
	watchtower_bob.chain_monitor.block_connected(&create_dummy_block(BlockHash::all_zeros(), 42, Vec::new()), HTLC_TIMEOUT_BROADCAST - 1);

	// Route another payment to generate another update with still previous HTLC pending
	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], 3000000);
	nodes[1].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[1], 1);

	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	{
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		if let ChannelPhase::Funded(ref mut channel) = get_channel_ref!(nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_1.2) {
			if let Ok(Some(update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].logger) {
				// Watchtower Alice should already have seen the block and reject the update
				assert_eq!(watchtower_alice.chain_monitor.update_channel(outpoint, &update), ChannelMonitorUpdateStatus::InProgress);
				assert_eq!(watchtower_bob.chain_monitor.update_channel(outpoint, &update), ChannelMonitorUpdateStatus::Completed);
				assert_eq!(nodes[0].chain_monitor.update_channel(outpoint, &update), ChannelMonitorUpdateStatus::Completed);
			} else { assert!(false); }
		} else {
			assert!(false);
		}
	}
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors!(nodes[0], 1);

	//// Provide one more block to watchtower Bob, expect broadcast of commitment and HTLC-Timeout
	watchtower_bob.chain_monitor.block_connected(&create_dummy_block(BlockHash::all_zeros(), 42, Vec::new()), HTLC_TIMEOUT_BROADCAST);

	// Watchtower Bob should have broadcast a commitment/HTLC-timeout
	let bob_state_y;
	{
		let mut txn = bob_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 2);
		bob_state_y = txn.remove(0);
	};

	// We confirm Bob's state Y on Alice, she should broadcast a HTLC-timeout
	let height = HTLC_TIMEOUT_BROADCAST + 1;
	connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
	check_closed_broadcast(&nodes[0], 1, true);
	check_closed_event!(&nodes[0], 1, ClosureReason::HTLCsTimedOut, false,
		[nodes[1].node.get_our_node_id()], 100000);
	watchtower_alice.chain_monitor.block_connected(&create_dummy_block(BlockHash::all_zeros(), 42, vec![bob_state_y.clone()]), height);
	check_added_monitors(&nodes[0], 1);
	{
		let htlc_txn = alice_broadcaster.txn_broadcast();
		assert_eq!(htlc_txn.len(), 1);
		check_spends!(htlc_txn[0], bob_state_y);
	}
}

#[test]
fn test_pre_lockin_no_chan_closed_update() {
	// Test that if a peer closes a channel in response to a funding_created message we don't
	// generate a channel update (as the channel cannot appear on chain without a funding_signed
	// message).
	//
	// Doing so would imply a channel monitor update before the initial channel monitor
	// registration, violating our API guarantees.
	//
	// Previously, full_stack_target managed to hit this case by opening then closing a channel,
	// then opening a second channel with the same funding output as the first (which is not
	// rejected because the first channel does not exist in the ChannelManager) and closing it
	// before receiving funding_signed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create an initial channel
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);
	let accept_chan_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_chan_msg);

	// Move the first channel through the funding flow...
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);

	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors!(nodes[0], 0);

	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	let channel_id = ChannelId::v1_from_funding_outpoint(crate::chain::transaction::OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index });
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id, data: "Hi".to_owned() });
	assert!(nodes[0].chain_monitor.added_monitors.lock().unwrap().is_empty());
	check_closed_event!(nodes[0], 2, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("Hi".to_string()) }, true,
		[nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_htlc_no_detection() {
	// This test is a mutation to underscore the detection logic bug we had
	// before #653. HTLC value routed is above the remaining balance, thus
	// inverting HTLC and `to_remote` output. HTLC will come second and
	// it wouldn't be seen by pre-#653 detection as we were enumerate()'ing
	// on a watched outputs vector (Vec<TxOut>) thus implicitly relying on
	// outputs order detection for correct spending children filtring.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 1_000_000);
	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 2_000_000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	assert_eq!(local_txn[0].output.len(), 3);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let block = create_dummy_block(nodes[0].best_block_hash(), 42, vec![local_txn[0].clone()]);
	connect_block(&nodes[0], &block);
	// We deliberately connect the local tx twice as this should provoke a failure calling
	// this test before #653 fix.
	chain::Listen::block_connected(&nodes[0].chain_monitor.chain_monitor, &block, nodes[0].best_block_info().1 + 1);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, vec![htlc_timeout.clone()]));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], our_payment_hash, false);
}

fn do_test_onchain_htlc_settlement_after_close(broadcast_alice: bool, go_onchain_before_fulfill: bool) {
	// If we route an HTLC, then learn the HTLC's preimage after the upstream channel has been
	// force-closed, we must claim that HTLC on-chain. (Given an HTLC forwarded from Alice --> Bob -->
	// Carol, Alice would be the upstream node, and Carol the downstream.)
	//
	// Steps of the test:
	// 1) Alice sends a HTLC to Carol through Bob.
	// 2) Carol doesn't settle the HTLC.
	// 3) If broadcast_alice is true, Alice force-closes her channel with Bob. Else Bob force closes.
	// Steps 4 and 5 may be reordered depending on go_onchain_before_fulfill.
	// 4) Bob sees the Alice's commitment on his chain or vice versa. An offered output is present
	//    but can't be claimed as Bob doesn't have yet knowledge of the preimage.
	// 5) Carol release the preimage to Bob off-chain.
	// 6) Bob claims the offered output on the broadcasted commitment.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_ab = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001);

	// Steps (1) and (2):
	// Send an HTLC Alice --> Bob --> Carol, but Carol doesn't settle the HTLC back.
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Check that Alice's commitment transaction now contains an output for this HTLC.
	let alice_txn = get_local_commitment_txn!(nodes[0], chan_ab.2);
	check_spends!(alice_txn[0], chan_ab.3);
	assert_eq!(alice_txn[0].output.len(), 2);
	check_spends!(alice_txn[1], alice_txn[0]); // 2nd transaction is a non-final HTLC-timeout
	assert_eq!(alice_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(alice_txn.len(), 2);

	// Steps (3) and (4):
	// If `go_onchain_before_fufill`, broadcast the relevant commitment transaction and check that Bob
	// responds by (1) broadcasting a channel update and (2) adding a new ChannelMonitor.
	let mut force_closing_node = 0; // Alice force-closes
	let mut counterparty_node = 1; // Bob if Alice force-closes

	// Bob force-closes
	if !broadcast_alice {
		force_closing_node = 1;
		counterparty_node = 0;
	}
	let error_message = "Channel force-closed";
	nodes[force_closing_node].node.force_close_broadcasting_latest_txn(&chan_ab.2, &nodes[counterparty_node].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[force_closing_node], true);
	check_added_monitors!(nodes[force_closing_node], 1);
	check_closed_event!(nodes[force_closing_node], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[counterparty_node].node.get_our_node_id()], 100000);
	if go_onchain_before_fulfill {
		let txn_to_broadcast = match broadcast_alice {
			true => alice_txn.clone(),
			false => get_local_commitment_txn!(nodes[1], chan_ab.2)
		};
		connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![txn_to_broadcast[0].clone()]));
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors!(nodes[1], 1);
			check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		}
	}

	// Step (5):
	// Carol then claims the funds and sends an update_fulfill message to Bob, and they go through the
	// process of removing the HTLC from their commitment transactions.
	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);

	let carol_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(carol_updates.update_add_htlcs.is_empty());
	assert!(carol_updates.update_fail_htlcs.is_empty());
	assert!(carol_updates.update_fail_malformed_htlcs.is_empty());
	assert!(carol_updates.update_fee.is_none());
	assert_eq!(carol_updates.update_fulfill_htlcs.len(), 1);

	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &carol_updates.update_fulfill_htlcs[0]);
	let went_onchain = go_onchain_before_fulfill || force_closing_node == 1;
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], if went_onchain { None } else { Some(1000) }, went_onchain, false);
	// If Alice broadcasted but Bob doesn't know yet, here he prepares to tell her about the preimage.
	if !go_onchain_before_fulfill && broadcast_alice {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &carol_updates.commitment_signed);
	// One monitor update for the preimage to update the Bob<->Alice channel, one monitor update
	// Carol<->Bob's updated commitment transaction info.
	check_added_monitors!(nodes[1], 2);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let bob_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let bob_updates = match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*updates).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bob_revocation);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bob_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let carol_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &carol_revocation);
	check_added_monitors!(nodes[1], 1);

	// If this test requires the force-closed channel to not be on-chain until after the fulfill,
	// here's where we put said channel's commitment tx on-chain.
	let mut txn_to_broadcast = alice_txn.clone();
	if !broadcast_alice { txn_to_broadcast = get_local_commitment_txn!(nodes[1], chan_ab.2); }
	if !go_onchain_before_fulfill {
		connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, vec![txn_to_broadcast[0].clone()]));
		// If Bob was the one to force-close, he will have already passed these checks earlier.
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors!(nodes[1], 1);
			check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
		}
		let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		if broadcast_alice {
			assert_eq!(bob_txn.len(), 1);
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
		} else {
			if nodes[1].connect_style.borrow().updates_best_block_first() {
				assert_eq!(bob_txn.len(), 3);
				assert_eq!(bob_txn[0].compute_txid(), bob_txn[1].compute_txid());
			} else {
				assert_eq!(bob_txn.len(), 2);
			}
			check_spends!(bob_txn[0], chan_ab.3);
		}
	}

	// Step (6):
	// Finally, check that Bob broadcasted a preimage-claiming transaction for the HTLC output on the
	// broadcasted commitment transaction.
	{
		let script_weight = match broadcast_alice {
			true => OFFERED_HTLC_SCRIPT_WEIGHT,
			false => ACCEPTED_HTLC_SCRIPT_WEIGHT
		};
		// If Alice force-closed, Bob only broadcasts a HTLC-output-claiming transaction. Otherwise,
		// Bob force-closed and broadcasts the commitment transaction along with a
		// HTLC-output-claiming transaction.
		let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		if broadcast_alice {
			assert_eq!(bob_txn.len(), 1);
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
			assert_eq!(bob_txn[0].input[0].witness.last().unwrap().len(), script_weight);
		} else {
			assert_eq!(bob_txn.len(), if nodes[1].connect_style.borrow().updates_best_block_first() { 3 } else { 2 });
			let htlc_tx = bob_txn.pop().unwrap();
			check_spends!(htlc_tx, txn_to_broadcast[0]);
			assert_eq!(htlc_tx.input[0].witness.last().unwrap().len(), script_weight);
		}
	}
}

#[test]
fn test_onchain_htlc_settlement_after_close() {
	do_test_onchain_htlc_settlement_after_close(true, true);
	do_test_onchain_htlc_settlement_after_close(false, true); // Technically redundant, but may as well
	do_test_onchain_htlc_settlement_after_close(true, false);
	do_test_onchain_htlc_settlement_after_close(false, false);
}

#[test]
fn test_duplicate_temporary_channel_id_from_different_peers() {
	// Tests that we can accept two different `OpenChannel` requests with the same
	// `temporary_channel_id`, as long as they are from different peers.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create an first channel channel
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg_chan_1_0 = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());

	// Create an second channel
	nodes[2].node.create_channel(nodes[0].node.get_our_node_id(), 100000, 10001, 43, None, None).unwrap();
	let mut open_chan_msg_chan_2_0 = get_event_msg!(nodes[2], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());

	// Modify the `OpenChannel` from `nodes[2]` to `nodes[0]` to ensure that it uses the same
	// `temporary_channel_id` as the `OpenChannel` from nodes[1] to nodes[0].
	open_chan_msg_chan_2_0.common_fields.temporary_channel_id = open_chan_msg_chan_1_0.common_fields.temporary_channel_id;

	// Assert that `nodes[0]` can accept both `OpenChannel` requests, even though they use the same
	// `temporary_channel_id` as they are from different peers.
	nodes[0].node.handle_open_channel(&nodes[1].node.get_our_node_id(), &open_chan_msg_chan_1_0);
	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::SendAcceptChannel { node_id, msg } => {
				assert_eq!(node_id, &nodes[1].node.get_our_node_id());
				assert_eq!(msg.common_fields.temporary_channel_id, open_chan_msg_chan_1_0.common_fields.temporary_channel_id);
			},
			_ => panic!("Unexpected event"),
		}
	}

	nodes[0].node.handle_open_channel(&nodes[2].node.get_our_node_id(), &open_chan_msg_chan_2_0);
	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::SendAcceptChannel { node_id, msg } => {
				assert_eq!(node_id, &nodes[2].node.get_our_node_id());
				assert_eq!(msg.common_fields.temporary_channel_id, open_chan_msg_chan_1_0.common_fields.temporary_channel_id);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_peer_funding_sidechannel() {
	// Test that if a peer somehow learns which txid we'll use for our channel funding before we
	// receive `funding_transaction_generated` the peer cannot cause us to crash. We'd previously
	// assumed that LDK would receive `funding_transaction_generated` prior to our peer learning
	// the txid and panicked if the peer tried to open a redundant channel to us with the same
	// funding outpoint.
	//
	// While this assumption is generally safe, some users may have out-of-band protocols where
	// they notify their LSP about a funding outpoint first, or this may be violated in the future
	// with collaborative transaction construction protocols, i.e. dual-funding.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let temp_chan_id_ab = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);
	let temp_chan_id_ca = exchange_open_accept_chan(&nodes[2], &nodes[0], 1_000_000, 0);

	let (_, tx, funding_output) =
		create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);

	let cs_funding_events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(cs_funding_events.len(), 1);
	match cs_funding_events[0] {
		Event::FundingGenerationReady { .. } => {}
		_ => panic!("Unexpected event {:?}", cs_funding_events),
	}

	nodes[2].node.funding_transaction_generated_unchecked(temp_chan_id_ca, nodes[0].node.get_our_node_id(), tx.clone(), funding_output.index).unwrap();
	let funding_created_msg = get_event_msg!(nodes[2], MessageSendEvent::SendFundingCreated, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_created(&nodes[2].node.get_our_node_id(), &funding_created_msg);
	get_event_msg!(nodes[0], MessageSendEvent::SendFundingSigned, nodes[2].node.get_our_node_id());
	expect_channel_pending_event(&nodes[0], &nodes[2].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);

	let res = nodes[0].node.funding_transaction_generated(temp_chan_id_ab, nodes[1].node.get_our_node_id(), tx.clone());
	let err_msg = format!("{:?}", res.unwrap_err());
	assert!(err_msg.contains("An existing channel using outpoint "));
	assert!(err_msg.contains(" is open with peer"));
	// Even though the last funding_transaction_generated errored, it still generated a
	// SendFundingCreated. However, when the peer responds with a funding_signed it will send the
	// appropriate error message.
	let as_funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &as_funding_created);
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());
	let reason = ClosureReason::ProcessingError { err: format!("An existing channel using outpoint {} is open with peer {}", funding_output, nodes[2].node.get_our_node_id()), };
	check_closed_events(&nodes[0], &[ExpectedCloseEvent::from_id_reason(ChannelId::v1_from_funding_outpoint(funding_output), true, reason)]);

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	get_err_msg(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_duplicate_conflicting_funding_from_second_peer() {
	// Test that if a user tries to fund a channel with a funding outpoint they'd previously used
	// we don't try to remove the previous ChannelMonitor. This is largely a test to ensure we
	// don't regress in the fuzzer, as such funding getting passed our outpoint-matches checks
	// implies the user (and our counterparty) has reused cryptographic keys across channels, which
	// we require the user not do.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let temp_chan_id = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);

	let (_, tx, funding_output) =
		create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);

	// Now that we have a funding outpoint, create a dummy `ChannelMonitor` and insert it into
	// nodes[0]'s ChainMonitor so that the initial `ChannelMonitor` write fails.
	let dummy_chan_id = create_chan_between_nodes(&nodes[2], &nodes[3]).3;
	let dummy_monitor = get_monitor!(nodes[2], dummy_chan_id).clone();
	nodes[0].chain_monitor.chain_monitor.watch_channel(funding_output, dummy_monitor).unwrap();

	nodes[0].node.funding_transaction_generated(temp_chan_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	// At this point, the channel should be closed, after having generated one monitor write (the
	// watch_channel call which failed), but zero monitor updates.
	check_added_monitors!(nodes[0], 1);
	get_err_msg(&nodes[0], &nodes[1].node.get_our_node_id());
	let err_reason = ClosureReason::ProcessingError { err: "Channel funding outpoint was a duplicate".to_owned() };
	check_closed_events(&nodes[0], &[ExpectedCloseEvent::from_id_reason(funding_signed_msg.channel_id, true, err_reason)]);
}

#[test]
fn test_duplicate_funding_err_in_funding() {
	// Test that if we have a live channel with one peer, then another peer comes along and tries
	// to create a second channel with the same txid we'll fail and not overwrite the
	// outpoint_to_peer map in `ChannelManager`.
	//
	// This was previously broken.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let (_, _, _, real_channel_id, funding_tx) = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let real_chan_funding_txo = chain::transaction::OutPoint { txid: funding_tx.compute_txid(), index: 0 };
	assert_eq!(ChannelId::v1_from_funding_outpoint(real_chan_funding_txo), real_channel_id);

	nodes[2].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[2], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	let node_c_temp_chan_id = open_chan_msg.common_fields.temporary_channel_id;
	open_chan_msg.common_fields.temporary_channel_id = real_channel_id;
	nodes[1].node.handle_open_channel(&nodes[2].node.get_our_node_id(), &open_chan_msg);
	let mut accept_chan_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[2].node.get_our_node_id());
	accept_chan_msg.common_fields.temporary_channel_id = node_c_temp_chan_id;
	nodes[2].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_chan_msg);

	// Now that we have a second channel with the same funding txo, send a bogus funding message
	// and let nodes[1] remove the inbound channel.
	let (_, funding_tx, _) = create_funding_transaction(&nodes[2], &nodes[1].node.get_our_node_id(), 100_000, 42);

	nodes[2].node.funding_transaction_generated(node_c_temp_chan_id, nodes[1].node.get_our_node_id(), funding_tx).unwrap();

	let mut funding_created_msg = get_event_msg!(nodes[2], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	funding_created_msg.temporary_channel_id = real_channel_id;
	// Make the signature invalid by changing the funding output
	funding_created_msg.funding_output_index += 10;
	nodes[1].node.handle_funding_created(&nodes[2].node.get_our_node_id(), &funding_created_msg);
	get_err_msg(&nodes[1], &nodes[2].node.get_our_node_id());
	let err = "Invalid funding_created signature from peer".to_owned();
	let reason = ClosureReason::ProcessingError { err };
	let expected_closing = ExpectedCloseEvent::from_id_reason(real_channel_id, false, reason);
	check_closed_events(&nodes[1], &[expected_closing]);

	assert_eq!(
		*nodes[1].node.outpoint_to_peer.lock().unwrap().get(&real_chan_funding_txo).unwrap(),
		nodes[0].node.get_our_node_id()
	);
}

#[test]
fn test_duplicate_chan_id() {
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

	// Create an initial channel
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// Try to create a second channel with the same temporary_channel_id as the first and check
	// that it is rejected.
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both the
				// first (valid) and second (invalid) channels are closed, given they both have
				// the same non-temporary channel_id. However, currently we do not, so we just
				// move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.common_fields.temporary_channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Move the first channel through the funding flow...
	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);

	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors!(nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

	let funding_outpoint = crate::chain::transaction::OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index };
	let channel_id = ChannelId::v1_from_funding_outpoint(funding_outpoint);

	// Now we have the first channel past funding_created (ie it has a txid-based channel_id, not a
	// temporary one).

	// First try to open a second channel with a temporary channel id equal to the txid-based one.
	// Technically this is allowed by the spec, but we don't support it and there's little reason
	// to. Still, it shouldn't cause any other issues.
	open_chan_msg.common_fields.temporary_channel_id = channel_id;
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.common_fields.temporary_channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Now try to create a second channel which has a duplicate funding output.
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_chan_2_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_2_msg);
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));
	create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42); // Get and check the FundingGenerationReady event

	let funding_created = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let mut a_peer_state = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		// Once we call `get_funding_created` the channel has a duplicate channel_id as
		// another channel in the ChannelManager - an invalid state. Thus, we'd panic later when we
		// try to create another channel. Instead, we drop the channel entirely here (leaving the
		// channelmanager in a possibly nonsense state instead).
		match a_peer_state.channel_by_id.remove(&open_chan_2_msg.common_fields.temporary_channel_id).unwrap() {
			ChannelPhase::UnfundedOutboundV1(mut chan) => {
				let logger = test_utils::TestLogger::new();
				chan.get_funding_created(tx.clone(), funding_outpoint, false, &&logger).map_err(|_| ()).unwrap()
			},
			_ => panic!("Unexpected ChannelPhase variant"),
		}.unwrap()
	};
	check_added_monitors!(nodes[0], 0);
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	// At this point we'll look up if the channel_id is present and immediately fail the channel
	// without trying to persist the `ChannelMonitor`.
	check_added_monitors!(nodes[1], 0);

	check_closed_events(&nodes[1], &[
		ExpectedCloseEvent::from_id_reason(funding_created.temporary_channel_id, false, ClosureReason::ProcessingError {
			err: "Already had channel with the new channel_id".to_owned()
		})
	]);

	// ...still, nodes[1] will reject the duplicate channel.
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// finally, finish creating the original channel and send a payment over it to make sure
	// everything is functional.
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());

	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 0);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);

	let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &as_update, &bs_update);

	send_payment(&nodes[0], &[&nodes[1]], 8000000);
}

#[test]
fn test_error_chans_closed() {
	// Test that we properly handle error messages, closing appropriate channels.
	//
	// Prior to #787 we'd allow a peer to make us force-close a channel we had with a different
	// peer. The "real" fix for that is to index channels with peers_ids, however in the mean time
	// we can test various edge cases around it to ensure we don't regress.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	let chan_3 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);

	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);
	assert_eq!(nodes[1].node.list_usable_channels().len(), 2);
	assert_eq!(nodes[2].node.list_usable_channels().len(), 1);

	// Closing a channel from a different peer has no effect
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: chan_3.2, data: "ERR".to_owned() });
	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);

	// Closing one channel doesn't impact others
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: chan_2.2, data: "ERR".to_owned() });
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], false);
	check_closed_event!(nodes[0], 1, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("ERR".to_string()) },
		[nodes[1].node.get_our_node_id()], 100000);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 2);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_1.2 || nodes[0].node.list_usable_channels()[1].channel_id == chan_1.2);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2 || nodes[0].node.list_usable_channels()[1].channel_id == chan_3.2);

	// A null channel ID should close all channels
	let _chan_4 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: ChannelId::new_zero(), data: "ERR".to_owned() });
	check_added_monitors!(nodes[0], 2);
	check_closed_event!(nodes[0], 2, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("ERR".to_string()) },
		[nodes[1].node.get_our_node_id(); 2], 100000);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	// Note that at this point users of a standard PeerHandler will end up calling
	// peer_disconnected.
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);
}

#[test]
fn test_invalid_funding_tx() {
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

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 10_000, 42, None, None).unwrap();
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id()));
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	let (temporary_channel_id, mut tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);

	// Create a witness program which can be spent by a 4-empty-stack-elements witness and which is
	// 136 bytes long. This matches our "accepted HTLC preimage spend" matching, previously causing
	// a panic as we'd try to extract a 32 byte preimage from a witness element without checking
	// its length.
	let mut wit_program: Vec<u8> = channelmonitor::deliberately_bogus_accepted_htlc_witness_program();
	let wit_program_script: ScriptBuf = wit_program.into();
	for output in tx.output.iter_mut() {
		// Make the confirmed funding transaction have a bogus script_pubkey
		output.script_pubkey = ScriptBuf::new_p2wsh(&wit_program_script.wscript_hash());
	}

	nodes[0].node.funding_transaction_generated_unchecked(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone(), 0).unwrap();
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id()));
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id()));
	check_added_monitors!(nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());

	let events_1 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 0);

	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

	let expected_err = "funding tx had wrong script/value or output index";
	confirm_transaction_at(&nodes[1], &tx, 1);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: expected_err.to_string() },
		[nodes[0].node.get_our_node_id()], 100000);
	check_added_monitors!(nodes[1], 1);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	if let MessageSendEvent::HandleError { node_id, action } = &events_2[0] {
		assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		if let msgs::ErrorAction::DisconnectPeer { msg } = action {
			assert_eq!(msg.as_ref().unwrap().data, "Channel closed because of an exception: ".to_owned() + expected_err);
		} else { panic!(); }
	} else { panic!(); }
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// Now confirm a spend of the (bogus) funding transaction. As long as the witness is 5 elements
	// long the ChannelMonitor will try to read 32 bytes from the second-to-last element, panicing
	// as its not 32 bytes long.
	let mut spend_tx = Transaction {
		version: Version::TWO, lock_time: LockTime::ZERO,
		input: tx.output.iter().enumerate().map(|(idx, _)| TxIn {
			previous_output: BitcoinOutPoint {
				txid: tx.compute_txid(),
				vout: idx as u32,
			},
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			witness: Witness::from_slice(&channelmonitor::deliberately_bogus_accepted_htlc_witness())
		}).collect(),
		output: vec![TxOut {
			value: Amount::from_sat(1000),
			script_pubkey: ScriptBuf::new(),
		}]
	};
	check_spends!(spend_tx, tx);
	mine_transaction(&nodes[1], &spend_tx);
}

#[test]
fn test_coinbase_funding_tx() {
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

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	// Create the coinbase funding transaction.
	let (temporary_channel_id, tx, _) = create_coinbase_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);

	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors!(nodes[0], 0);
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	check_added_monitors!(nodes[0], 1);

	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
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
	let _ = &nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id()));

	confirm_transaction_at(&nodes[1], &tx, 1);
	connect_blocks(&nodes[1], COINBASE_MATURITY - 2);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	connect_blocks(&nodes[1], 1);
	expect_channel_ready_event(&nodes[1], &nodes[0].node.get_our_node_id());
	create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
}

fn do_test_tx_confirmed_skipping_blocks_immediate_broadcast(test_height_before_timelock: bool) {
	// In the first version of the chain::Confirm interface, after a refactor was made to not
	// broadcast CSV-locked transactions until their CSV lock is up, we wouldn't reliably broadcast
	// transactions after a `transactions_confirmed` call. Specifically, if the chain, provided via
	// `best_block_updated` is at height N, and a transaction output which we wish to spend at
	// height N-1 (due to a CSV to height N-1) is provided at height N, we will not broadcast the
	// spending transaction until height N+1 (or greater). This was due to the way
	// `ChannelMonitor::transactions_confirmed` worked, only checking if we should broadcast a
	// spending transaction at the height the input transaction was confirmed at, not whether we
	// should broadcast a spending transaction at the current height.
	// A second, similar, issue involved failing HTLCs backwards - because we only provided the
	// height at which transactions were confirmed to `OnchainTx::update_claims_view`, it wasn't
	// aware that the anti-reorg-delay had, in fact, already expired, waiting to fail-backwards
	// until we learned about an additional block.
	//
	// As an additional check, if `test_height_before_timelock` is set, we instead test that we
	// aren't broadcasting transactions too early (ie not broadcasting them at all).
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = ConnectStyle::BestBlockFirstSkippingBlocks;

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_announce, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2);
	let (_, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id());
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	let error_message = "Channel force-closed";
	nodes[1].node.force_close_broadcasting_latest_txn(&channel_id, &nodes[2].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, [nodes[2].node.get_our_node_id()], 100000);
	check_added_monitors!(nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);

	let conf_height = nodes[1].best_block_info().1;
	if !test_height_before_timelock {
		connect_blocks(&nodes[1], 24 * 6);
	}
	nodes[1].chain_monitor.chain_monitor.transactions_confirmed(
		&nodes[1].get_block_header(conf_height), &[(0, &node_txn[0])], conf_height);
	if test_height_before_timelock {
		// If we confirmed the close transaction, but timelocks have not yet expired, we should not
		// generate any events or broadcast any transactions
		assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
		assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	} else {
		// We should broadcast an HTLC transaction spending our funding transaction first
		let spending_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(spending_txn.len(), 2);
		let htlc_tx = if spending_txn[0].compute_txid() == node_txn[0].compute_txid() {
			&spending_txn[1]
		} else {
			&spending_txn[0]
		};
		check_spends!(htlc_tx, node_txn[0]);
		// We should also generate a SpendableOutputs event with the to_self output (as its
		// timelock is up).
		let descriptor_spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
		assert_eq!(descriptor_spend_txn.len(), 1);

		// If we also discover that the HTLC-Timeout transaction was confirmed some time ago, we
		// should immediately fail-backwards the HTLC to the previous hop, without waiting for an
		// additional block built on top of the current chain.
		nodes[1].chain_monitor.chain_monitor.transactions_confirmed(
			&nodes[1].get_block_header(conf_height + 1), &[(0, htlc_tx)], conf_height + 1);
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: channel_id }]);
		check_added_monitors!(nodes[1], 1);

		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
		expect_payment_failed_with_update!(nodes[0], payment_hash, false, chan_announce.contents.short_channel_id, true);
	}
}

#[test]
fn test_tx_confirmed_skipping_blocks_immediate_broadcast() {
	do_test_tx_confirmed_skipping_blocks_immediate_broadcast(false);
	do_test_tx_confirmed_skipping_blocks_immediate_broadcast(true);
}

fn do_test_dup_htlc_second_rejected(test_for_second_fail_panic: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features()).unwrap();
	let route = get_route!(nodes[0], payment_params, 10_000).unwrap();

	let (our_payment_preimage, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(&nodes[1]);

	{
		nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	}
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], our_payment_hash, our_payment_secret, 10_000);

	{
		// Note that we use a different PaymentId here to allow us to duplicativly pay
		nodes[0].node.send_payment_with_route(route, our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_secret.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		// At this point, nodes[1] would notice it has too much value for the payment. It will
		// assume the second is a privacy attack (no longer particularly relevant
		// post-payment_secrets) and fail back the new HTLC. Previously, it'd also have failed back
		// the first HTLC delivered above.
	}

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();

	if test_for_second_fail_panic {
		// Now we go fail back the first HTLC from the user end.
		nodes[1].node.fail_htlc_backwards(&our_payment_hash);

		let expected_destinations = vec![
			HTLCDestination::FailedPayment { payment_hash: our_payment_hash },
			HTLCDestination::FailedPayment { payment_hash: our_payment_hash },
		];
		expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1],  expected_destinations);
		nodes[1].node.process_pending_htlc_forwards();

		check_added_monitors!(nodes[1], 1);
		let fail_updates_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert_eq!(fail_updates_1.update_fail_htlcs.len(), 2);

		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates_1.update_fail_htlcs[0]);
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates_1.update_fail_htlcs[1]);
		commitment_signed_dance!(nodes[0], nodes[1], fail_updates_1.commitment_signed, false);

		let failure_events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(failure_events.len(), 4);
		if let Event::PaymentPathFailed { .. } = failure_events[0] {} else { panic!(); }
		if let Event::PaymentFailed { .. } = failure_events[1] {} else { panic!(); }
		if let Event::PaymentPathFailed { .. } = failure_events[2] {} else { panic!(); }
		if let Event::PaymentFailed { .. } = failure_events[3] {} else { panic!(); }
	} else {
		// Let the second HTLC fail and claim the first
		expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);
		nodes[1].node.process_pending_htlc_forwards();

		check_added_monitors!(nodes[1], 1);
		let fail_updates_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates_1.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], fail_updates_1.commitment_signed, false);

		expect_payment_failed_conditions(&nodes[0], our_payment_hash, true, PaymentFailedConditions::new());

		claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage);
	}
}

#[test]
fn test_dup_htlc_second_fail_panic() {
	// Previously, if we received two HTLCs back-to-back, where the second overran the expected
	// value for the payment, we'd fail back both HTLCs after generating a `PaymentClaimable` event.
	// Then, if the user failed the second payment, they'd hit a "tried to fail an already failed
	// HTLC" debug panic. This tests for this behavior, checking that only one HTLC is auto-failed.
	do_test_dup_htlc_second_rejected(true);
}

#[test]
fn test_dup_htlc_second_rejected() {
	// Test that if we receive a second HTLC for an MPP payment that overruns the payment amount we
	// simply reject the second HTLC but are still able to claim the first HTLC.
	do_test_dup_htlc_second_rejected(false);
}

#[test]
fn test_inconsistent_mpp_params() {
	// Test that if we recieve two HTLCs with different payment parameters we fail back the first
	// such HTLC and allow the second to stay.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
	let chan_2_3 =create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0);

	let payment_params = PaymentParameters::from_node_id(nodes[3].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features()).unwrap();
	let mut route = get_route!(nodes[0], payment_params, 15_000_000).unwrap();
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == nodes[1].node.get_our_node_id() {
			core::cmp::Ordering::Less } else { core::cmp::Ordering::Greater }
	});

	let (our_payment_preimage, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(&nodes[3]);

	let cur_height = nodes[0].best_block_info().1;
	let payment_id = PaymentId([42; 32]);

	let session_privs = {
		// We create a fake route here so that we start with three pending HTLCs, which we'll
		// ultimately have, just not right away.
		let mut dup_route = route.clone();
		dup_route.paths.push(route.paths[1].clone());
		nodes[0].node.test_add_new_pending_payment(our_payment_hash,
			RecipientOnionFields::secret_only(our_payment_secret), payment_id, &dup_route).unwrap()
	};
	nodes[0].node.test_send_payment_along_path(&route.paths[0], &our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), 15_000_000, cur_height, payment_id,
		&None, session_privs[0]).unwrap();
	check_added_monitors!(nodes[0], 1);

	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 15_000_000, our_payment_hash, Some(our_payment_secret), events.pop().unwrap(), false, None);
	}
	assert!(nodes[3].node.get_and_clear_pending_events().is_empty());

	nodes[0].node.test_send_payment_along_path(&route.paths[1], &our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), 14_000_000, cur_height, payment_id, &None, session_privs[1]).unwrap();
	check_added_monitors!(nodes[0], 1);

	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[2].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[2], nodes[0], payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[2]);
		check_added_monitors!(nodes[2], 1);

		let mut events = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[3].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[3], 0);
		commitment_signed_dance!(nodes[3], nodes[2], payment_event.commitment_msg, true, true);

		// At this point, nodes[3] should notice the two HTLCs don't contain the same total payment
		// amount. It will assume the second is a privacy attack (no longer particularly relevant
		// post-payment_secrets) and fail back the new HTLC.
	}
	expect_pending_htlcs_forwardable_ignore!(nodes[3]);
	nodes[3].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[3], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);
	nodes[3].node.process_pending_htlc_forwards();

	check_added_monitors!(nodes[3], 1);

	let fail_updates_1 = get_htlc_update_msgs!(nodes[3], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &fail_updates_1.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[2], nodes[3], fail_updates_1.commitment_signed, false);

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_2_3.2 }]);
	check_added_monitors!(nodes[2], 1);

	let fail_updates_2 = get_htlc_update_msgs!(nodes[2], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &fail_updates_2.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[2], fail_updates_2.commitment_signed, false);

	expect_payment_failed_conditions(&nodes[0], our_payment_hash, true, PaymentFailedConditions::new().mpp_parts_remain());

	nodes[0].node.test_send_payment_along_path(&route.paths[1], &our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), 15_000_000, cur_height, payment_id,
		&None, session_privs[2]).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 15_000_000, our_payment_hash, Some(our_payment_secret), events.pop().unwrap(), true, None);

	do_claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], our_payment_preimage)
	);
	expect_payment_sent(&nodes[0], our_payment_preimage, Some(None), true, true);
}

#[test]
fn test_double_partial_claim() {
	// Test what happens if a node receives a payment, generates a PaymentClaimable event, the HTLCs
	// time out, the sender resends only some of the MPP parts, then the user processes the
	// PaymentClaimable event, ensuring they don't inadvertently claim only part of the full payment
	// amount.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0);

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 15_000_000);
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == nodes[1].node.get_our_node_id() {
			core::cmp::Ordering::Less } else { core::cmp::Ordering::Greater }
	});

	send_along_route_with_secret(&nodes[0], route.clone(), &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], 15_000_000, payment_hash, payment_secret);
	// nodes[3] has now received a PaymentClaimable event...which it will take some (exorbitant)
	// amount of time to respond to.

	// Connect some blocks to time out the payment
	connect_blocks(&nodes[3], TEST_FINAL_CLTV);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // To get the same height for sending later

	let failed_destinations = vec![
		HTLCDestination::FailedPayment { payment_hash },
		HTLCDestination::FailedPayment { payment_hash },
	];
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[3], failed_destinations);

	pass_failed_payment_back(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_hash, PaymentFailureReason::RecipientRejected);

	// nodes[1] now retries one of the two paths...
	nodes[0].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 2);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let node_1_msgs = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 15_000_000, payment_hash, Some(payment_secret), node_1_msgs, false, None);

	// At this point nodes[3] has received one half of the payment, and the user goes to handle
	// that PaymentClaimable event they got hours ago and never handled...we should refuse to claim.
	nodes[3].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[3], 0);
	assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
}

/// The possible events which may trigger a `max_dust_htlc_exposure` breach
#[derive(Clone, Copy, PartialEq)]
enum ExposureEvent {
	/// Breach occurs at HTLC forwarding (see `send_htlc`)
	AtHTLCForward,
	/// Breach occurs at HTLC reception (see `update_add_htlc`)
	AtHTLCReception,
	/// Breach occurs at outbound update_fee (see `send_update_fee`)
	AtUpdateFeeOutbound,
}

fn do_test_max_dust_htlc_exposure(dust_outbound_balance: bool, exposure_breach_event: ExposureEvent, on_holder_tx: bool, multiplier_dust_limit: bool, apply_excess_fee: bool) {
	// Test that we properly reject dust HTLC violating our `max_dust_htlc_exposure_msat`
	// policy.
	//
	// At HTLC forward (`send_payment()`), if the sum of the trimmed-to-dust HTLC inbound and
	// trimmed-to-dust HTLC outbound balance and this new payment as included on next
	// counterparty commitment are above our `max_dust_htlc_exposure_msat`, we'll reject the
	// update. At HTLC reception (`update_add_htlc()`), if the sum of the trimmed-to-dust HTLC
	// inbound and trimmed-to-dust HTLC outbound balance and this new received HTLC as included
	// on next counterparty commitment are above our `max_dust_htlc_exposure_msat`, we'll fail
	// the update. Note, we return a `temporary_channel_failure` (0x1000 | 7), as the channel
	// might be available again for HTLC processing once the dust bandwidth has cleared up.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut config = test_default_channel_config();

	// We hard-code the feerate values here but they're re-calculated furter down and asserted.
	// If the values ever change below these constants should simply be updated.
	const AT_FEE_OUTBOUND_HTLCS: u64 = 20;
	let nondust_htlc_count_in_limit =
	if exposure_breach_event == ExposureEvent::AtUpdateFeeOutbound  {
		AT_FEE_OUTBOUND_HTLCS
	} else { 0 };
	let initial_feerate = if apply_excess_fee { 253 * 2 } else { 253 };
	let expected_dust_buffer_feerate = initial_feerate + 2530;
	let mut commitment_tx_cost = commit_tx_fee_msat(initial_feerate - 253, nondust_htlc_count_in_limit, &ChannelTypeFeatures::empty());
	commitment_tx_cost +=
		if on_holder_tx {
			htlc_success_tx_weight(&ChannelTypeFeatures::empty())
		} else {
			htlc_timeout_tx_weight(&ChannelTypeFeatures::empty())
		} * (initial_feerate as u64 - 253) / 1000 * nondust_htlc_count_in_limit;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = initial_feerate;
	}
	config.channel_config.max_dust_htlc_exposure = if multiplier_dust_limit {
		// Default test fee estimator rate is 253 sat/kw, so we set the multiplier to 5_000_000 / 253
		// to get roughly the same initial value as the default setting when this test was
		// originally written.
		MaxDustHTLCExposure::FeeRateMultiplier((5_000_000 + commitment_tx_cost) / 253)
	} else { MaxDustHTLCExposure::FixedLimitMsat(5_000_000 + commitment_tx_cost) };
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 500_000_000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.common_fields.max_htlc_value_in_flight_msat = 50_000_000;
	open_channel.common_fields.max_accepted_htlcs = 60;
	if on_holder_tx {
		open_channel.common_fields.dust_limit_satoshis = 546;
	}
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	let channel_type_features = ChannelTypeFeatures::only_static_remote_key();

	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);

	if on_holder_tx {
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		match get_channel_ref!(nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, temporary_channel_id) {
			ChannelPhase::UnfundedOutboundV1(chan) => {
				chan.context.holder_dust_limit_satoshis = 546;
			},
			_ => panic!("Unexpected ChannelPhase variant"),
		}
	}

	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id()));
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id()));
	check_added_monitors!(nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());

	let (channel_ready, channel_id) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &as_update, &bs_update);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 253;
	}

	// Fetch a route in advance as we will be unable to once we're unable to send.
	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000);

	let (dust_buffer_feerate, max_dust_htlc_exposure_msat) = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		let chan = chan_lock.channel_by_id.get(&channel_id).unwrap();
		(chan.context().get_dust_buffer_feerate(None) as u64,
		chan.context().get_max_dust_htlc_exposure_msat(253))
	};
	assert_eq!(dust_buffer_feerate, expected_dust_buffer_feerate as u64);
	let dust_outbound_htlc_on_holder_tx_msat: u64 = (dust_buffer_feerate * htlc_timeout_tx_weight(&channel_type_features) / 1000 + open_channel.common_fields.dust_limit_satoshis - 1) * 1000;
	let dust_outbound_htlc_on_holder_tx: u64 = max_dust_htlc_exposure_msat / dust_outbound_htlc_on_holder_tx_msat;

	// Substract 3 sats for multiplier and 2 sats for fixed limit to make sure we are 50% below the dust limit.
	// This is to make sure we fully use the dust limit. If we don't, we could end up with `dust_ibd_htlc_on_holder_tx` being 1
	// while `max_dust_htlc_exposure_msat` is not equal to `dust_outbound_htlc_on_holder_tx_msat`.
	let dust_inbound_htlc_on_holder_tx_msat: u64 = (dust_buffer_feerate * htlc_success_tx_weight(&channel_type_features) / 1000 + open_channel.common_fields.dust_limit_satoshis - if multiplier_dust_limit { 3 } else { 2 }) * 1000;
	let dust_inbound_htlc_on_holder_tx: u64 = max_dust_htlc_exposure_msat / dust_inbound_htlc_on_holder_tx_msat;

	// This test was written with a fixed dust value here, which we retain, but assert that it is,
	// indeed, dust on both transactions.
	let dust_htlc_on_counterparty_tx: u64 = 4;
	let dust_htlc_on_counterparty_tx_msat: u64 = 1_250_000;
	let calcd_dust_htlc_on_counterparty_tx_msat: u64 = (dust_buffer_feerate * htlc_timeout_tx_weight(&channel_type_features) / 1000 + open_channel.common_fields.dust_limit_satoshis - if multiplier_dust_limit { 3 } else { 2 }) * 1000;
	assert!(dust_htlc_on_counterparty_tx_msat < dust_inbound_htlc_on_holder_tx_msat);
	assert!(dust_htlc_on_counterparty_tx_msat < calcd_dust_htlc_on_counterparty_tx_msat);

	if on_holder_tx {
		if dust_outbound_balance {
			// Outbound dust threshold: 2223 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + holder's `dust_limit_satoshis`)
			// Outbound dust balance: 4372 sats
			// Note, we need sent payment to be above outbound dust threshold on counterparty_tx of 2132 sats
			for _ in 0..dust_outbound_htlc_on_holder_tx {
				let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], dust_outbound_htlc_on_holder_tx_msat);
				nodes[0].node.send_payment_with_route(route, payment_hash,
					RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
			}
		} else {
			// Inbound dust threshold: 2324 sats (`dust_buffer_feerate` * HTLC_SUCCESS_TX_WEIGHT / 1000 + holder's `dust_limit_satoshis`)
			// Inbound dust balance: 4372 sats
			// Note, we need sent payment to be above outbound dust threshold on counterparty_tx of 2031 sats
			for _ in 0..dust_inbound_htlc_on_holder_tx {
				route_payment(&nodes[1], &[&nodes[0]], dust_inbound_htlc_on_holder_tx_msat);
			}
		}
	} else {
		if dust_outbound_balance {
			// Outbound dust threshold: 2132 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + counteparty's `dust_limit_satoshis`)
			// Outbound dust balance: 5000 sats
			for _ in 0..dust_htlc_on_counterparty_tx - 1 {
				let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], dust_htlc_on_counterparty_tx_msat);
				nodes[0].node.send_payment_with_route(route, payment_hash,
					RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
			}
		} else {
			// Inbound dust threshold: 2031 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + counteparty's `dust_limit_satoshis`)
			// Inbound dust balance: 5000 sats
			for _ in 0..dust_htlc_on_counterparty_tx - 1 {
				route_payment(&nodes[1], &[&nodes[0]], dust_htlc_on_counterparty_tx_msat);
			}
		}
	}

	if exposure_breach_event == ExposureEvent::AtHTLCForward {
		route.paths[0].hops.last_mut().unwrap().fee_msat =
			if on_holder_tx { dust_outbound_htlc_on_holder_tx_msat } else { dust_htlc_on_counterparty_tx_msat + 1 };
		// With default dust exposure: 5000 sats
		if on_holder_tx {
			unwrap_send_err!(nodes[0].node.send_payment_with_route(route, payment_hash,
					RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)
				), true, APIError::ChannelUnavailable { .. }, {});
		} else {
			unwrap_send_err!(nodes[0].node.send_payment_with_route(route, payment_hash,
					RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)
				), true, APIError::ChannelUnavailable { .. }, {});
		}
	} else if exposure_breach_event == ExposureEvent::AtHTLCReception {
		let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[1], nodes[0], if on_holder_tx { dust_inbound_htlc_on_holder_tx_msat } else { dust_htlc_on_counterparty_tx_msat + 4 });
		nodes[1].node.send_payment_with_route(route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(nodes[1], 1);
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.remove(0));
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
		// With default dust exposure: 5000 sats
		if on_holder_tx {
			// Outbound dust balance: 6399 sats
			let dust_inbound_overflow = dust_inbound_htlc_on_holder_tx_msat * (dust_inbound_htlc_on_holder_tx + 1);
			let dust_outbound_overflow = dust_outbound_htlc_on_holder_tx_msat * dust_outbound_htlc_on_holder_tx + dust_inbound_htlc_on_holder_tx_msat;
			nodes[0].logger.assert_log("lightning::ln::channel", format!("Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on holder commitment tx", if dust_outbound_balance { dust_outbound_overflow } else { dust_inbound_overflow }, max_dust_htlc_exposure_msat), 1);
		} else {
			// Outbound dust balance: 5200 sats
			nodes[0].logger.assert_log("lightning::ln::channel",
				format!("Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on counterparty commitment tx",
					dust_htlc_on_counterparty_tx_msat * dust_htlc_on_counterparty_tx + commitment_tx_cost + 4,
					max_dust_htlc_exposure_msat), 1);
		}
	} else if exposure_breach_event == ExposureEvent::AtUpdateFeeOutbound {
		route.paths[0].hops.last_mut().unwrap().fee_msat = 2_500_000;
		// For the multiplier dust exposure limit, since it scales with feerate,
		// we need to add a lot of HTLCs that will become dust at the new feerate
		// to cross the threshold.
		for _ in 0..AT_FEE_OUTBOUND_HTLCS {
			let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[1], Some(1_000), None);
			nodes[0].node.send_payment_with_route(route.clone(), payment_hash,
				RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		}
		{
			let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
			*feerate_lock = *feerate_lock * 10;
		}
		nodes[0].node.timer_tick_occurred();
		check_added_monitors!(nodes[0], 1);
		nodes[0].logger.assert_log_contains("lightning::ln::channel", "Cannot afford to send new feerate at 2530 without infringing max dust htlc exposure", 1);
	}

	let _ = nodes[0].node.get_and_clear_pending_msg_events();
	let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
	added_monitors.clear();
}

fn do_test_max_dust_htlc_exposure_by_threshold_type(multiplier_dust_limit: bool, apply_excess_fee: bool) {
	do_test_max_dust_htlc_exposure(true, ExposureEvent::AtHTLCForward, true, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(false, ExposureEvent::AtHTLCForward, true, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(false, ExposureEvent::AtHTLCReception, true, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(false, ExposureEvent::AtHTLCReception, false, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(true, ExposureEvent::AtHTLCForward, false, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(true, ExposureEvent::AtHTLCReception, false, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(true, ExposureEvent::AtHTLCReception, true, multiplier_dust_limit, apply_excess_fee);
	do_test_max_dust_htlc_exposure(false, ExposureEvent::AtHTLCForward, false, multiplier_dust_limit, apply_excess_fee);
	if !multiplier_dust_limit && !apply_excess_fee {
		// Because non-dust HTLC transaction fees are included in the dust exposure, trying to
		// increase the fee to hit a higher dust exposure with a
		// `MaxDustHTLCExposure::FeeRateMultiplier` is no longer super practical, so we skip these
		// in the `multiplier_dust_limit` case.
		do_test_max_dust_htlc_exposure(true, ExposureEvent::AtUpdateFeeOutbound, true, multiplier_dust_limit, apply_excess_fee);
		do_test_max_dust_htlc_exposure(true, ExposureEvent::AtUpdateFeeOutbound, false, multiplier_dust_limit, apply_excess_fee);
		do_test_max_dust_htlc_exposure(false, ExposureEvent::AtUpdateFeeOutbound, false, multiplier_dust_limit, apply_excess_fee);
		do_test_max_dust_htlc_exposure(false, ExposureEvent::AtUpdateFeeOutbound, true, multiplier_dust_limit, apply_excess_fee);
	}
}

#[test]
fn test_max_dust_htlc_exposure() {
	do_test_max_dust_htlc_exposure_by_threshold_type(false, false);
	do_test_max_dust_htlc_exposure_by_threshold_type(false, true);
	do_test_max_dust_htlc_exposure_by_threshold_type(true, false);
	do_test_max_dust_htlc_exposure_by_threshold_type(true, true);
}

#[test]
fn test_nondust_htlc_fees_are_dust() {
	// Test that the transaction fees paid in nondust HTLCs count towards our dust limit
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut config = test_default_channel_config();
	// Set the dust limit to the default value
	config.channel_config.max_dust_htlc_exposure =
		MaxDustHTLCExposure::FeeRateMultiplier(10_000);
	// Make sure the HTLC limits don't get in the way
	config.channel_handshake_limits.min_max_accepted_htlcs = 400;
	config.channel_handshake_config.our_max_accepted_htlcs = 400;
	config.channel_handshake_config.our_htlc_minimum_msat = 1;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config), Some(config), Some(config)]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create a channel from 1 -> 0 but immediately push all of the funds towards 0
	let chan_id_1 = create_announced_chan_between_nodes(&nodes, 1, 0).2;
	while nodes[1].node.list_channels()[0].next_outbound_htlc_limit_msat > 0 {
		send_payment(&nodes[1], &[&nodes[0]], nodes[1].node.list_channels()[0].next_outbound_htlc_limit_msat);
	}

	// First get the channel one HTLC_VALUE HTLC away from the dust limit by sending dust HTLCs
	// repeatedly until we run out of space.
	const HTLC_VALUE: u64 = 1_000_000; // Doesn't matter, tune until the test passes
	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], HTLC_VALUE).0;

	while nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat == 0 {
		route_payment(&nodes[0], &[&nodes[1]], HTLC_VALUE);
	}
	assert_ne!(nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat, 0,
		"We don't want to run out of ability to send because of some non-dust limit");
	assert!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len() < 10,
		"We should be able to fill our dust limit without too many HTLCs");

	let dust_limit = nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	assert_ne!(nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat, 0,
		"Make sure we are able to send once we clear one HTLC");

	// At this point we have somewhere between dust_limit and dust_limit * 2 left in our dust
	// exposure limit, and we want to max that out using non-dust HTLCs.
	let commitment_tx_per_htlc_cost =
		htlc_success_tx_weight(&ChannelTypeFeatures::empty()) * 253;
	let max_htlcs_remaining = dust_limit * 2 / commitment_tx_per_htlc_cost;
	assert!(max_htlcs_remaining < 30,
		"We should be able to fill our dust limit without too many HTLCs");
	for i in 0..max_htlcs_remaining + 1 {
		assert_ne!(i, max_htlcs_remaining);
		if nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat < dust_limit {
			// We found our limit, and it was less than max_htlcs_remaining!
			// At this point we can only send dust HTLCs as any non-dust HTLCs will overuse our
			// remaining dust exposure.
			break;
		}
		route_payment(&nodes[0], &[&nodes[1]], dust_limit * 2);
	}

	// At this point non-dust HTLCs are no longer accepted from node 0 -> 1, we also check that
	// such HTLCs can't be routed over the same channel either.
	create_announced_chan_between_nodes(&nodes, 2, 0);
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[2], nodes[1], dust_limit * 2);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[2].node.send_payment_with_route(route, payment_hash, onion, PaymentId([0; 32])).unwrap();
	check_added_monitors(&nodes[2], 1);
	let send = SendEvent::from_node(&nodes[2]);

	nodes[0].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &send.msgs[0]);
	commitment_signed_dance!(nodes[0], nodes[2], send.commitment_msg, false, true);

	expect_pending_htlcs_forwardable!(nodes[0]);
	check_added_monitors(&nodes[0], 1);
	let node_id_1 = nodes[1].node.get_our_node_id();
	expect_htlc_handling_failed_destinations!(
		nodes[0].node.get_and_clear_pending_events(),
		&[HTLCDestination::NextHopChannel { node_id: Some(node_id_1), channel_id: chan_id_1 }]
	);

	let fail = get_htlc_update_msgs(&nodes[0], &nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[0].node.get_our_node_id(), &fail.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[2], nodes[0], fail.commitment_signed, false);
	expect_payment_failed_conditions(&nodes[2], payment_hash, false, PaymentFailedConditions::new());
}


#[test]
fn test_non_final_funding_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_message);
	let accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel_message);

	let best_height = nodes[0].node.best_block.read().unwrap().height;

	let chan_id = *nodes[0].network_chan_count.borrow();
	let events = nodes[0].node.get_and_clear_pending_events();
	let input = TxIn { previous_output: BitcoinOutPoint::null(), script_sig: bitcoin::ScriptBuf::new(), sequence: Sequence(1), witness: Witness::from_slice(&[&[1]]) };
	assert_eq!(events.len(), 1);
	let mut tx = match events[0] {
		Event::FundingGenerationReady { ref channel_value_satoshis, ref output_script, .. } => {
			// Timelock the transaction _beyond_ the best client height + 1.
			Transaction { version: Version(chan_id as i32), lock_time: LockTime::from_height(best_height + 2).unwrap(), input: vec![input], output: vec![TxOut {
				value: Amount::from_sat(*channel_value_satoshis), script_pubkey: output_script.clone(),
			}]}
		},
		_ => panic!("Unexpected event"),
	};
	// Transaction should fail as it's evaluated as non-final for propagation.
	match nodes[0].node.funding_transaction_generated(temp_channel_id, nodes[1].node.get_our_node_id(), tx.clone()) {
		Err(APIError::APIMisuseError { err }) => {
			assert_eq!(format!("Funding transaction absolute timelock is non-final"), err);
		},
		_ => panic!()
	}
	let err = "Error in transaction funding: Misuse error: Funding transaction absolute timelock is non-final".to_owned();
	check_closed_events(&nodes[0], &[ExpectedCloseEvent::from_id_reason(temp_channel_id, false, ClosureReason::ProcessingError { err })]);
	assert_eq!(get_err_msg(&nodes[0], &nodes[1].node.get_our_node_id()).data, "Failed to fund channel");
}

#[test]
fn test_non_final_funding_tx_within_headroom() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_message);
	let accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel_message);

	let best_height = nodes[0].node.best_block.read().unwrap().height;

	let chan_id = *nodes[0].network_chan_count.borrow();
	let events = nodes[0].node.get_and_clear_pending_events();
	let input = TxIn { previous_output: BitcoinOutPoint::null(), script_sig: bitcoin::ScriptBuf::new(), sequence: Sequence(1), witness: Witness::from_slice(&[[1]]) };
	assert_eq!(events.len(), 1);
	let mut tx = match events[0] {
		Event::FundingGenerationReady { ref channel_value_satoshis, ref output_script, .. } => {
			// Timelock the transaction within a +1 headroom from the best block.
			Transaction { version: Version(chan_id as i32), lock_time: LockTime::from_consensus(best_height + 1), input: vec![input], output: vec![TxOut {
				value: Amount::from_sat(*channel_value_satoshis), script_pubkey: output_script.clone(),
			}]}
		},
		_ => panic!("Unexpected event"),
	};

	// Transaction should be accepted if it's in a +1 headroom from best block.
	assert!(nodes[0].node.funding_transaction_generated(temp_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).is_ok());
	get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
}

#[test]
fn accept_busted_but_better_fee() {
	// If a peer sends us a fee update that is too low, but higher than our previous channel
	// feerate, we should accept it. In the future we may want to consider closing the channel
	// later, but for now we only accept the update.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

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
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_fee.as_ref().unwrap());
			commitment_signed_dance!(nodes[1], nodes[0], commitment_signed, false);
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
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_fee.as_ref().unwrap());
			commitment_signed_dance!(nodes[1], nodes[0], commitment_signed, false);
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
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, .. }, .. } => {
			nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_fee.as_ref().unwrap());
			check_closed_event!(nodes[1], 1, ClosureReason::PeerFeerateTooLow {
				peer_feerate_sat_per_kw: 1000, required_feerate_sat_per_kw: 5000,
			}, [nodes[0].node.get_our_node_id()], 100000);
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors!(nodes[1], 1);
		},
		_ => panic!("Unexpected event"),
	};
}

fn do_payment_with_custom_min_final_cltv_expiry(valid_delta: bool, use_user_hash: bool) {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let min_final_cltv_expiry_delta = 120;
	let final_cltv_expiry_delta = if valid_delta { min_final_cltv_expiry_delta + 2 } else {
		min_final_cltv_expiry_delta - 2 };
	let recv_value = 100_000;

	create_chan_between_nodes(&nodes[0], &nodes[1]);

	let payment_parameters = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), final_cltv_expiry_delta as u32);
	let (payment_hash, payment_preimage, payment_secret) = if use_user_hash {
		let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1],
			Some(recv_value), Some(min_final_cltv_expiry_delta));
		(payment_hash, payment_preimage, payment_secret)
	} else {
		let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(recv_value), 7200, Some(min_final_cltv_expiry_delta)).unwrap();
		(payment_hash, nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap(), payment_secret)
	};
	let route = get_route!(nodes[0], payment_parameters, recv_value).unwrap();
	nodes[0].node.send_payment_with_route(route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	if valid_delta {
		expect_payment_claimable!(nodes[1], payment_hash, payment_secret, recv_value, if use_user_hash {
			None } else { Some(payment_preimage) }, nodes[1].node.get_our_node_id());

		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);
	} else {
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);

		check_added_monitors!(nodes[1], 1);

		let fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], fail_updates.commitment_signed, false, true);

		expect_payment_failed!(nodes[0], payment_hash, true);
	}
}

#[test]
fn test_payment_with_custom_min_cltv_expiry_delta() {
	do_payment_with_custom_min_final_cltv_expiry(false, false);
	do_payment_with_custom_min_final_cltv_expiry(false, true);
	do_payment_with_custom_min_final_cltv_expiry(true, false);
	do_payment_with_custom_min_final_cltv_expiry(true, true);
}

#[test]
fn test_disconnects_peer_awaiting_response_ticks() {
	// Tests that nodes which are awaiting on a response critical for channel responsiveness
	// disconnect their counterparty after `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Asserts a disconnect event is queued to the user.
	let check_disconnect_event = |node: &Node, should_disconnect: bool| {
		let disconnect_event = node.node.get_and_clear_pending_msg_events().iter().find_map(|event|
			if let MessageSendEvent::HandleError { action, .. } = event {
				if let msgs::ErrorAction::DisconnectPeerWithWarning { .. } = action {
					Some(())
				} else {
					None
				}
			} else {
				None
			}
		);
		assert_eq!(disconnect_event.is_some(), should_disconnect);
	};

	// Fires timer ticks ensuring we only attempt to disconnect peers after reaching
	// `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let check_disconnect = |node: &Node| {
		// No disconnect without any timer ticks.
		check_disconnect_event(node, false);

		// No disconnect with 1 timer tick less than required.
		for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS - 1 {
			node.node.timer_tick_occurred();
			check_disconnect_event(node, false);
		}

		// Disconnect after reaching the required ticks.
		node.node.timer_tick_occurred();
		check_disconnect_event(node, true);

		// Disconnect again on the next tick if the peer hasn't been disconnected yet.
		node.node.timer_tick_occurred();
		check_disconnect_event(node, true);
	};

	create_chan_between_nodes(&nodes[0], &nodes[1]);

	// We'll start by performing a fee update with Alice (nodes[0]) on the channel.
	*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(&nodes[0], 1);
	let alice_fee_update = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), alice_fee_update.update_fee.as_ref().unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &alice_fee_update.commitment_signed);
	check_added_monitors!(&nodes[1], 1);

	// This will prompt Bob (nodes[1]) to respond with his `CommitmentSigned` and `RevokeAndACK`.
	let (bob_revoke_and_ack, bob_commitment_signed) = get_revoke_commit_msgs!(&nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bob_revoke_and_ack);
	check_added_monitors!(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bob_commitment_signed);
	check_added_monitors(&nodes[0], 1);

	// Alice then needs to send her final `RevokeAndACK` to complete the commitment dance. We
	// pretend Bob hasn't received the message and check whether he'll disconnect Alice after
	// reaching `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let alice_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	check_disconnect(&nodes[1]);

	// Now, we'll reconnect them to test awaiting a `ChannelReestablish` message.
	//
	// Note that since the commitment dance didn't complete above, Alice is expected to resend her
	// final `RevokeAndACK` to Bob to complete it.
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	let bob_init = msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	};
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &bob_init, true).unwrap();
	let alice_init = msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	};
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &alice_init, true).unwrap();

	// Upon reconnection, Alice sends her `ChannelReestablish` to Bob. Alice, however, hasn't
	// received Bob's yet, so she should disconnect him after reaching
	// `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let alice_channel_reestablish = get_event_msg!(
		nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id()
	);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &alice_channel_reestablish);
	check_disconnect(&nodes[0]);

	// Bob now sends his `ChannelReestablish` to Alice to resume the channel and consider it "live".
	let bob_channel_reestablish = nodes[1].node.get_and_clear_pending_msg_events().iter().find_map(|event|
		if let MessageSendEvent::SendChannelReestablish { node_id, msg } = event {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			Some(msg.clone())
		} else {
			None
		}
	).unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bob_channel_reestablish);

	// Sanity check that Alice won't disconnect Bob since she's no longer waiting for any messages.
	for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
		nodes[0].node.timer_tick_occurred();
		check_disconnect_event(&nodes[0], false);
	}

	// However, Bob is still waiting on Alice's `RevokeAndACK`, so he should disconnect her after
	// reaching `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	check_disconnect(&nodes[1]);

	// Finally, have Bob process the last message.
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &alice_revoke_and_ack);
	check_added_monitors(&nodes[1], 1);

	// At this point, neither node should attempt to disconnect each other, since they aren't
	// waiting on any messages.
	for node in &nodes {
		for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
			node.node.timer_tick_occurred();
			check_disconnect_event(node, false);
		}
	}
}

#[test]
fn test_remove_expired_outbound_unfunded_channels() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_message);
	let accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel_message);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => (),
		_ => panic!("Unexpected event"),
	};

	// Asserts the outbound channel has been removed from a nodes[0]'s peer state map.
	let check_outbound_channel_existence = |should_exist: bool| {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		assert_eq!(chan_lock.channel_by_id.contains_key(&temp_channel_id), should_exist);
	};

	// Channel should exist without any timer ticks.
	check_outbound_channel_existence(true);

	// Channel should exist with 1 timer tick less than required.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS - 1 {
		nodes[0].node.timer_tick_occurred();
		check_outbound_channel_existence(true)
	}

	// Remove channel after reaching the required ticks.
	nodes[0].node.timer_tick_occurred();
	check_outbound_channel_existence(false);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
			assert_eq!(msg.data, "Force-closing pending channel due to timeout awaiting establishment handshake");
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_event(&nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(false) }, false, &[nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_remove_expired_inbound_unfunded_channels() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let temp_channel_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_message);
	let accept_channel_message = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel_message);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => (),
		_ => panic!("Unexpected event"),
	};

	// Asserts the inbound channel has been removed from a nodes[1]'s peer state map.
	let check_inbound_channel_existence = |should_exist: bool| {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		assert_eq!(chan_lock.channel_by_id.contains_key(&temp_channel_id), should_exist);
	};

	// Channel should exist without any timer ticks.
	check_inbound_channel_existence(true);

	// Channel should exist with 1 timer tick less than required.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS - 1 {
		nodes[1].node.timer_tick_occurred();
		check_inbound_channel_existence(true)
	}

	// Remove channel after reaching the required ticks.
	nodes[1].node.timer_tick_occurred();
	check_inbound_channel_existence(false);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
			assert_eq!(msg.data, "Force-closing pending channel due to timeout awaiting establishment handshake");
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_event(&nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(false) }, false, &[nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn test_channel_close_when_not_timely_accepted() {
	// Create network of two nodes
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Simulate peer-disconnects mid-handshake
	// The channel is initiated from the node 0 side,
	// but the nodes disconnect before node 1 could send accept channel
	let create_chan_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(open_channel_msg.common_fields.temporary_channel_id, create_chan_id);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

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
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(false) }, [nodes[1].node.get_our_node_id()], 100000);
	assert_eq!(nodes[0].node.list_channels().len(), 0);

	{
		// Since accept channel message was never received
		// The channel should be forced close by now from node 0 side
		// and the peer removed from per_peer_state
		let node_0_per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		assert_eq!(node_0_per_peer_state.len(), 0);
	}
}

#[test]
fn test_rebroadcast_open_channel_when_reconnect_mid_handshake() {
	// Create network of two nodes
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Simulate peer-disconnects mid-handshake
	// The channel is initiated from the node 0 side,
	// but the nodes disconnect before node 1 could send accept channel
	let create_chan_id = nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(open_channel_msg.common_fields.temporary_channel_id, create_chan_id);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	// Make sure that we have not removed the OutboundV1Channel from node[0] immediately.
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Since channel was inbound from node[1] perspective, it should have been immediately dropped.
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// The peers now reconnect
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Make sure the SendOpenChannel message is added to node_0 pending message events
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::SendOpenChannel { msg, .. } => assert_eq!(msg, &open_channel_msg),
		_ => panic!("Unexpected message."),
	}
}

fn do_test_multi_post_event_actions(do_reload: bool) {
	// Tests handling multiple post-Event actions at once.
	// There is specific code in ChannelManager to handle channels where multiple post-Event
	// `ChannelMonitorUpdates` are pending at once. This test exercises that code.
	//
	// Specifically, we test calling `get_and_clear_pending_events` while there are two
	// PaymentSents from different channels and one channel has two pending `ChannelMonitorUpdate`s
	// - one from an RAA and one from an inbound commitment_signed.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let (persister, chain_monitor);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes_0_deserialized;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 0, 2).2;

	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	send_payment(&nodes[0], &[&nodes[2]], 1_000_000);

	let (our_payment_preimage, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[2]], 1_000_000);

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 1_000_000);

	nodes[2].node.claim_funds(payment_preimage_2);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_2, 1_000_000);

	for dest in &[1, 2] {
		let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[*dest], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(&nodes[*dest].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[*dest], htlc_fulfill_updates.commitment_signed, false);
		check_added_monitors(&nodes[0], 0);
	}

	let (route, payment_hash_3, _, payment_secret_3) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 100_000);
	let payment_id = PaymentId(payment_hash_3.0);
	nodes[1].node.send_payment_with_route(route, payment_hash_3,
		RecipientOnionFields::secret_only(payment_secret_3), payment_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let send_event = SendEvent::from_node(&nodes[1]);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event.commitment_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	if do_reload {
		let nodes_0_serialized = nodes[0].node.encode();
		let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
		let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_2).encode();
		reload_node!(nodes[0], test_default_channel_config(), &nodes_0_serialized, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], persister, chain_monitor, nodes_0_deserialized);

		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
		nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[2]));
	}

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 4);
	if let Event::PaymentSent { payment_preimage, .. } = events[0] {
		assert!(payment_preimage == our_payment_preimage || payment_preimage == payment_preimage_2);
	} else { panic!(); }
	if let Event::PaymentSent { payment_preimage, .. } = events[1] {
		assert!(payment_preimage == our_payment_preimage || payment_preimage == payment_preimage_2);
	} else { panic!(); }
	if let Event::PaymentPathSuccessful { .. } = events[2] {} else { panic!(); }
	if let Event::PaymentPathSuccessful { .. } = events[3] {} else { panic!(); }

	// After the events are processed, the ChannelMonitorUpdates will be released and, upon their
	// completion, we'll respond to nodes[1] with an RAA + CS.
	get_revoke_commit_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	check_added_monitors(&nodes[0], 3);
}

#[test]
fn test_multi_post_event_actions() {
	do_test_multi_post_event_actions(true);
	do_test_multi_post_event_actions(false);
}

#[test]
fn test_batch_channel_open() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(&nodes[0], &[
		(&nodes[1], 100_000, 0, 42, None),
		(&nodes[2], 200_000, 0, 43, None),
	]);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);

	// Go through the funding_created and funding_signed flow with node 2.
	nodes[2].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msgs[1]);
	check_added_monitors(&nodes[2], 1);
	expect_channel_pending_event(&nodes[2], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_funding_signed(&nodes[2].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before persisting all monitors has been
	// completed.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);
	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);

	// Complete the persistence of the monitor.
	nodes[0].chain_monitor.complete_sole_pending_chan_update(
		&ChannelId::v1_from_funding_outpoint(OutPoint { txid: tx.compute_txid(), index: 1 })
	);
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
		} if counterparty_node_id == &nodes[1].node.get_our_node_id(),
	)));
	assert!(events.iter().any(|e| matches!(
		*e,
		crate::events::Event::ChannelPending {
			ref counterparty_node_id,
			..
		} if counterparty_node_id == &nodes[2].node.get_our_node_id(),
	)));
}

#[test]
fn test_close_in_funding_batch() {
	// This test ensures that if one of the channels
	// in the batch closes, the complete batch will close.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(&nodes[0], &[
		(&nodes[1], 100_000, 0, 42, None),
		(&nodes[2], 200_000, 0, 43, None),
	]);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);

	// Force-close the channel for which we've completed the initial monitor.
	let funding_txo_1 = OutPoint { txid: tx.compute_txid(), index: 0 };
	let funding_txo_2 = OutPoint { txid: tx.compute_txid(), index: 1 };
	let channel_id_1 = ChannelId::v1_from_funding_outpoint(funding_txo_1);
	let channel_id_2 = ChannelId::v1_from_funding_outpoint(funding_txo_2);
	let error_message = "Channel force-closed";
	nodes[0].node.force_close_broadcasting_latest_txn(&channel_id_1, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();

	// The monitor should become closed.
	check_added_monitors(&nodes[0], 1);
	{
		let mut monitor_updates = nodes[0].chain_monitor.monitor_updates.lock().unwrap();
		let monitor_updates_1 = monitor_updates.get(&channel_id_1).unwrap();
		assert_eq!(monitor_updates_1.len(), 1);
		assert_eq!(monitor_updates_1[0].update_id, CLOSED_CHANNEL_UPDATE_ID);
	}

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError { .. } => (),
		_ => panic!("Unexpected message."),
	}

	// We broadcast the commitment transaction as part of the force-close.
	{
		let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(broadcasted_txs.len(), 1);
		assert!(broadcasted_txs[0].compute_txid() != tx.compute_txid());
		assert_eq!(broadcasted_txs[0].input.len(), 1);
		assert_eq!(broadcasted_txs[0].input[0].previous_output.txid, tx.compute_txid());
	}

	// All channels in the batch should close immediately.
	check_closed_events(&nodes[0], &[
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
	]);

	// Ensure the channels don't exist anymore.
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn test_batch_funding_close_after_funding_signed() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Initiate channel opening and create the batch channel funding transaction.
	let (tx, funding_created_msgs) = create_batch_channel_funding(&nodes[0], &[
		(&nodes[1], 100_000, 0, 42, None),
		(&nodes[2], 200_000, 0, 43, None),
	]);

	// Go through the funding_created and funding_signed flow with node 1.
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msgs[0]);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// Go through the funding_created and funding_signed flow with node 2.
	nodes[2].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msgs[1]);
	check_added_monitors(&nodes[2], 1);
	expect_channel_pending_event(&nodes[2], &nodes[0].node.get_our_node_id());

	let funding_signed_msg = get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_funding_signed(&nodes[2].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);

	// The transaction should not have been broadcast before all channels are ready.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 0);

	// Force-close the channel for which we've completed the initial monitor.
	let funding_txo_1 = OutPoint { txid: tx.compute_txid(), index: 0 };
	let funding_txo_2 = OutPoint { txid: tx.compute_txid(), index: 1 };
	let channel_id_1 = ChannelId::v1_from_funding_outpoint(funding_txo_1);
	let channel_id_2 = ChannelId::v1_from_funding_outpoint(funding_txo_2);
	let error_message = "Channel force-closed";
	nodes[0].node.force_close_broadcasting_latest_txn(&channel_id_1, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_added_monitors(&nodes[0], 2);
	{
		let mut monitor_updates = nodes[0].chain_monitor.monitor_updates.lock().unwrap();
		let monitor_updates_1 = monitor_updates.get(&channel_id_1).unwrap();
		assert_eq!(monitor_updates_1.len(), 1);
		assert_eq!(monitor_updates_1[0].update_id, CLOSED_CHANNEL_UPDATE_ID);
		let monitor_updates_2 = monitor_updates.get(&channel_id_2).unwrap();
		assert_eq!(monitor_updates_2.len(), 1);
		assert_eq!(monitor_updates_2[0].update_id, CLOSED_CHANNEL_UPDATE_ID);
	}
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError { .. } => (),
		_ => panic!("Unexpected message."),
	}

	// We broadcast the commitment transaction as part of the force-close.
	{
		let broadcasted_txs = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(broadcasted_txs.len(), 1);
		assert!(broadcasted_txs[0].compute_txid() != tx.compute_txid());
		assert_eq!(broadcasted_txs[0].input.len(), 1);
		assert_eq!(broadcasted_txs[0].input[0].previous_output.txid, tx.compute_txid());
	}

	// All channels in the batch should close immediately.
	check_closed_events(&nodes[0], &[
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
	]);

	// Ensure the channels don't exist anymore.
	assert!(nodes[0].node.list_channels().is_empty());
}

fn do_test_funding_and_commitment_tx_confirm_same_block(confirm_remote_commitment: bool) {
	// Tests that a node will forget the channel (when it only requires 1 confirmation) if the
	// funding and commitment transaction confirm in the same block.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut min_depth_1_block_cfg = test_default_channel_config();
	min_depth_1_block_cfg.channel_handshake_config.minimum_depth = 1;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(min_depth_1_block_cfg), Some(min_depth_1_block_cfg)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);
	let chan_id = ChannelId::v1_from_funding_outpoint(chain::transaction::OutPoint { txid: funding_tx.compute_txid(), index: 0 });

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	let (closing_node, other_node) = if confirm_remote_commitment {
		(&nodes[1], &nodes[0])
	} else {
		(&nodes[0], &nodes[1])
	};
	let error_message = "Channel force-closed";
	closing_node.node.force_close_broadcasting_latest_txn(&chan_id, &other_node.node.get_our_node_id(), error_message.to_string()).unwrap();
	let mut msg_events = closing_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events.pop().unwrap() {
		MessageSendEvent::HandleError { action: msgs::ErrorAction::SendErrorMessage { .. }, .. } => {},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors(closing_node, 1);
	check_closed_event(closing_node, 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[other_node.node.get_our_node_id()], 1_000_000);

	let commitment_tx = {
		let mut txn = closing_node.tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		let commitment_tx = txn.pop().unwrap();
		check_spends!(commitment_tx, funding_tx);
		commitment_tx
	};

	mine_transactions(&nodes[0], &[&funding_tx, &commitment_tx]);
	mine_transactions(&nodes[1], &[&funding_tx, &commitment_tx]);

	check_closed_broadcast(other_node, 1, true);
	check_added_monitors(other_node, 1);
	check_closed_event(other_node, 1, ClosureReason::CommitmentTxConfirmed, false, &[closing_node.node.get_our_node_id()], 1_000_000);

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
}

#[test]
fn test_funding_and_commitment_tx_confirm_same_block() {
	do_test_funding_and_commitment_tx_confirm_same_block(false);
	do_test_funding_and_commitment_tx_confirm_same_block(true);
}

#[test]
fn test_accept_inbound_channel_errors_queued() {
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

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
	let events = nodes[1].node.get_and_clear_pending_events();
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			match nodes[1].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 23) {
				Err(APIError::ChannelUnavailable { err: _ }) => (),
				_ => panic!(),
			}
		}
		_ => panic!("Unexpected event"),
	}
	assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
		open_channel_msg.common_fields.temporary_channel_id);
}

#[test]
fn test_manual_funding_abandon() {
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_config.minimum_depth = 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg), Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).is_ok());
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);
	let (temporary_channel_id, _tx, funding_outpoint) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);
	nodes[0].node.unsafe_manual_funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), funding_outpoint).unwrap();
	check_added_monitors!(nodes[0], 0);

	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	let err = msgs::ErrorMessage { channel_id: funding_signed.channel_id, data: "".to_string() };
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &err);

	let close_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(close_events.len(), 2);
	assert!(close_events.iter().any(|ev| matches!(ev, Event::ChannelClosed { .. })));
	assert!(close_events.iter().any(|ev| match ev {
		Event::DiscardFunding { channel_id, funding_info: FundingInfo::OutPoint { outpoint } } => {
			assert_eq!(*channel_id, err.channel_id);
			assert_eq!(*outpoint, funding_outpoint);
			true
		}
		_ => false,
	}));
}

#[test]
fn test_funding_signed_event() {
	let mut cfg = UserConfig::default();
	cfg.channel_handshake_config.minimum_depth = 1;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg), Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).is_ok());
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);
	let (temporary_channel_id, tx, funding_outpoint) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);
	nodes[0].node.unsafe_manual_funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), funding_outpoint).unwrap();
	check_added_monitors!(nodes[0], 0);

	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	check_added_monitors!(nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	check_added_monitors!(nodes[0], 1);
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
			assert_eq!(*&nodes[1].node.get_our_node_id(), *counterparty_node_id);
		},
		_ => panic!("Unexpected event"),
	};

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	let as_channel_ready = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, nodes[0].node.get_our_node_id());
	nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_channel_ready);
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
	nodes[0].node.handle_channel_ready(&nodes[1].node.get_our_node_id(), &as_channel_ready);

	expect_channel_ready_event(&nodes[0], &nodes[1].node.get_our_node_id());
	expect_channel_ready_event(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

