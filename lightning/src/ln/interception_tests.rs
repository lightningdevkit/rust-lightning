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

use crate::events::{Event, HTLCHandlingFailureReason, HTLCHandlingFailureType};
use crate::ln::channelmanager::PaymentId;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler};
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::routing::router::PaymentParameters;
use crate::util::config::HTLCInterceptionFlags;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ForwardingMod {
	FeeTooLow,
	CLTVBelowConfig,
	CLTVBelowMin,
}

fn do_test_htlc_interception_flags(
	flags_bitmask: u8, flag: HTLCInterceptionFlags, modification: Option<ForwardingMod>,
) {
	use HTLCInterceptionFlags as Flag;

	assert_eq!((flag as isize).count_ones(), 1, "We can only test one type of HTLC at once");

	// Tests that the `htlc_interception_flags` bitmask given by `flags_bitmask` correctly
	// intercepts (or doesn't intercept) an HTLC which is of type `flag`
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut intercept_config = test_default_channel_config();
	intercept_config.htlc_interception_flags = flags_bitmask;
	intercept_config.channel_config.forwarding_fee_base_msat = 1000;
	intercept_config.channel_config.cltv_expiry_delta = 6 * 24;
	intercept_config.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_config), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let inbound_private = match flag {
		Flag::FromPrivateChannels => {
			create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 0);
			true
		},
		_ => {
			create_announced_chan_between_nodes(&nodes, 0, 1);
			false
		},
	};

	let node_0_id = nodes[0].node.get_our_node_id();
	let node_1_id = nodes[1].node.get_our_node_id();
	let node_2_id = nodes[2].node.get_our_node_id();

	// First open the right type of channel (and get it in the right state) for the bit we're
	// testing.
	let (target_scid, target_chan_id, outbound_private_for_known_scids) = match flag {
		Flag::ToOfflinePrivateChannels
		| Flag::ToOnlinePrivateChannels
		| Flag::FromPublicToPrivateChannels => {
			create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 0);
			let chan_id = nodes[2].node.list_channels()[0].channel_id;
			let scid = nodes[2].node.list_channels()[0].short_channel_id.unwrap();
			if flag == Flag::ToOfflinePrivateChannels {
				nodes[1].node.peer_disconnected(node_2_id);
				nodes[2].node.peer_disconnected(node_1_id);
			}
			(scid, chan_id, Some(true))
		},
		Flag::ToInterceptSCIDs
		| Flag::ToPublicChannels
		| Flag::FromPrivateChannels
		| Flag::FromPublicToPublicChannels
		| Flag::ToUnknownSCIDs => {
			let (chan_upd, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2);
			if flag == Flag::ToInterceptSCIDs {
				(nodes[1].node.get_intercept_scid(), chan_id, None)
			} else if flag == Flag::ToUnknownSCIDs {
				(42424242, chan_id, None)
			} else {
				(chan_upd.contents.short_channel_id, chan_id, Some(false))
			}
		},
		_ => panic!("Combined flags aren't allowed"),
	};

	// Start every node on the same block height to ensure we don't hit spurious CLTV issues
	connect_blocks(&nodes[0], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	// Send the HTLC from nodes[0] to nodes[1] and process it to generate the interception (if
	// we're set to intercept it).
	let amt_msat = 100_000;
	let bolt11 = nodes[2].node.create_bolt11_invoice(Default::default()).unwrap();
	let pay_params = PaymentParameters::from_bolt11_invoice(&bolt11);
	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], pay_params, amt_msat);
	route.paths[0].hops[1].short_channel_id = target_scid;

	let mut should_intercept = false;
	for a_flag in ALL_FLAGS {
		if flags_bitmask & (a_flag as u8) != 0 {
			match a_flag {
				Flag::ToInterceptSCIDs => {
					should_intercept |= flag == Flag::ToInterceptSCIDs;
				},
				Flag::ToOfflinePrivateChannels => {
					should_intercept |= flag == Flag::ToOfflinePrivateChannels;
				},
				Flag::ToOnlinePrivateChannels => {
					should_intercept |= flag != Flag::ToOfflinePrivateChannels
						&& outbound_private_for_known_scids == Some(true);
				},
				Flag::ToPublicChannels => {
					should_intercept |= outbound_private_for_known_scids == Some(false);
				},
				Flag::ToUnknownSCIDs => {
					should_intercept |= flag == Flag::ToUnknownSCIDs;
				},
				Flag::FromPrivateChannels => {
					should_intercept |= inbound_private;
				},
				Flag::FromPublicToPrivateChannels => {
					should_intercept |=
						!inbound_private && outbound_private_for_known_scids == Some(true);
				},
				Flag::FromPublicToPublicChannels => {
					should_intercept |=
						!inbound_private && outbound_private_for_known_scids == Some(false);
				},
				_ => panic!("Combined flags aren't allowed"),
			}
		}
	}

	match modification {
		Some(ForwardingMod::FeeTooLow) => {
			assert!(should_intercept, "No reason to test failing if we aren't trying to intercept");
			route.paths[0].hops[0].fee_msat = 500;
		},
		Some(ForwardingMod::CLTVBelowConfig) => {
			route.paths[0].hops[0].cltv_expiry_delta = 6 * 12;
			assert!(should_intercept, "No reason to test failing if we aren't trying to intercept");
		},
		Some(ForwardingMod::CLTVBelowMin) => {
			route.paths[0].hops[0].cltv_expiry_delta = 6;
		},
		None => {},
	}

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let payment_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(node_0_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);

	if should_intercept && modification.is_none() {
		// If we were set to intercept, check that we got an interception event then
		// forward the HTLC on to nodes[2] and claim the payment.
		let intercept_id;
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "{events:?}");
		if let Event::HTLCIntercepted { intercept_id: id, requested_next_hop_scid, .. } = &events[0]
		{
			assert_eq!(*requested_next_hop_scid, target_scid,
				"Bitmask {flags_bitmask:#x}: Expected interception for bit {flag:?} to target SCID {target_scid}");
			intercept_id = *id;
		} else {
			panic!("{events:?}");
		}

		if flag == Flag::ToOfflinePrivateChannels {
			let mut reconnect_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
			reconnect_args.send_channel_ready = (true, true);
			reconnect_nodes(reconnect_args);
		}

		nodes[1]
			.node
			.forward_intercepted_htlc(intercept_id, &target_chan_id, node_2_id, amt_msat)
			.unwrap();
		expect_and_process_pending_htlcs(&nodes[1], false);
		check_added_monitors(&nodes[1], 1);

		let forward_ev = SendEvent::from_node(&nodes[1]);
		nodes[2].node.handle_update_add_htlc(node_1_id, &forward_ev.msgs[0]);
		do_commitment_signed_dance(&nodes[2], &nodes[1], &forward_ev.commitment_msg, false, true);

		nodes[2].node.process_pending_htlc_forwards();
		expect_payment_claimable!(nodes[2], payment_hash, payment_secret, amt_msat);
		claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
	} else {
		// If we were not set to intercept, check that the HTLC either failed or was
		// automatically forwarded as appropriate.
		match (modification, flag) {
			(
				None,
				Flag::ToOnlinePrivateChannels
				| Flag::ToPublicChannels
				| Flag::FromPrivateChannels
				| Flag::FromPublicToPrivateChannels
				| Flag::FromPublicToPublicChannels,
			) => {
				check_added_monitors(&nodes[1], 1);

				let forward_ev = SendEvent::from_node(&nodes[1]);
				assert_eq!(forward_ev.node_id, node_2_id);
				nodes[2].node.handle_update_add_htlc(node_1_id, &forward_ev.msgs[0]);
				let commitment = &forward_ev.commitment_msg;
				do_commitment_signed_dance(&nodes[2], &nodes[1], commitment, false, true);

				nodes[2].node.process_pending_htlc_forwards();
				expect_payment_claimable!(nodes[2], payment_hash, payment_secret, amt_msat);
				claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
			},
			_ => {
				let events = nodes[1].node.get_and_clear_pending_events();
				let reason_from_mod = match modification {
					Some(ForwardingMod::FeeTooLow) => Some(LocalHTLCFailureReason::FeeInsufficient),
					Some(ForwardingMod::CLTVBelowConfig) => {
						Some(LocalHTLCFailureReason::IncorrectCLTVExpiry)
					},
					Some(ForwardingMod::CLTVBelowMin) => {
						Some(LocalHTLCFailureReason::IncorrectCLTVExpiry)
					},
					None => None,
				};
				let (expected_failure_type, reason);
				if flag == Flag::ToOfflinePrivateChannels {
					expected_failure_type = HTLCHandlingFailureType::Forward {
						node_id: Some(node_2_id),
						channel_id: target_chan_id,
					};
					reason = reason_from_mod.unwrap_or(LocalHTLCFailureReason::PeerOffline);
				} else if flag == Flag::ToInterceptSCIDs {
					expected_failure_type = HTLCHandlingFailureType::InvalidForward {
						requested_forward_scid: target_scid,
					};
					reason = reason_from_mod.unwrap_or(LocalHTLCFailureReason::UnknownNextPeer);
				} else if flag == Flag::ToUnknownSCIDs {
					expected_failure_type = HTLCHandlingFailureType::InvalidForward {
						requested_forward_scid: target_scid,
					};
					reason = reason_from_mod.unwrap_or(LocalHTLCFailureReason::UnknownNextPeer);
				} else {
					expected_failure_type = HTLCHandlingFailureType::Forward {
						node_id: Some(node_2_id),
						channel_id: target_chan_id,
					};
					reason = reason_from_mod
						.expect("We should only fail because of a mod or unknown next-hop");
				}
				if let Event::HTLCHandlingFailed { failure_reason, failure_type, .. } = &events[0] {
					assert_eq!(*failure_reason, Some(HTLCHandlingFailureReason::Local { reason }));
					assert_eq!(*failure_type, expected_failure_type);
				} else {
					panic!("{events:?}");
				}

				check_added_monitors(&nodes[1], 1);
				let fail_msgs = get_htlc_update_msgs(&nodes[1], &node_0_id);
				nodes[0].node.handle_update_fail_htlc(node_1_id, &fail_msgs.update_fail_htlcs[0]);
				let commitment = fail_msgs.commitment_signed;
				do_commitment_signed_dance(&nodes[0], &nodes[1], &commitment, true, true);
				expect_payment_failed!(nodes[0], payment_hash, false);
			},
		}
	}
}

const MAX_BITMASK: u8 = HTLCInterceptionFlags::AllValidHTLCs as u8;
const ALL_FLAGS: [HTLCInterceptionFlags; 8] = [
	HTLCInterceptionFlags::ToInterceptSCIDs,
	HTLCInterceptionFlags::ToOfflinePrivateChannels,
	HTLCInterceptionFlags::ToOnlinePrivateChannels,
	HTLCInterceptionFlags::ToPublicChannels,
	HTLCInterceptionFlags::ToUnknownSCIDs,
	HTLCInterceptionFlags::FromPrivateChannels,
	HTLCInterceptionFlags::FromPublicToPrivateChannels,
	HTLCInterceptionFlags::FromPublicToPublicChannels,
];
#[test]
fn check_all_flags() {
	let mut all_flag_bits = 0;
	for flag in ALL_FLAGS {
		all_flag_bits |= flag as isize;
	}
	assert_eq!(all_flag_bits, MAX_BITMASK as isize, "all flags must test all bits");
}

fn test_htlc_interception_flags_subrange<I: Iterator<Item = u8>>(r: I) {
	// Test all 2^5 = 32 combinations of the HTLCInterceptionFlags bitmask
	// For each combination, test 5 different HTLC forwards and verify correct interception behavior
	for flags_bitmask in r {
		for flag in ALL_FLAGS {
			do_test_htlc_interception_flags(flags_bitmask, flag, None);
		}
	}
}

#[test]
fn test_htlc_interception_flags_a() {
	test_htlc_interception_flags_subrange(0..MAX_BITMASK / 4);
}

#[test]
fn test_htlc_interception_flags_b() {
	test_htlc_interception_flags_subrange(MAX_BITMASK / 4..MAX_BITMASK / 2);
}

#[test]
fn test_htlc_interception_flags_c() {
	test_htlc_interception_flags_subrange(MAX_BITMASK / 2..MAX_BITMASK / 4 * 3);
}

#[test]
fn test_htlc_interception_flags_d() {
	test_htlc_interception_flags_subrange(MAX_BITMASK / 4 * 3..=MAX_BITMASK);
}

#[test]
fn test_htlc_bad_for_chan_config() {
	// Test that interception won't be done if an HTLC fails to meet the target channel's channel
	// config.
	let have_chan_flags = [
		HTLCInterceptionFlags::ToOfflinePrivateChannels,
		HTLCInterceptionFlags::ToOnlinePrivateChannels,
		HTLCInterceptionFlags::ToPublicChannels,
		HTLCInterceptionFlags::FromPrivateChannels,
		HTLCInterceptionFlags::FromPublicToPrivateChannels,
		HTLCInterceptionFlags::FromPublicToPublicChannels,
	];
	for flag in have_chan_flags {
		do_test_htlc_interception_flags(flag as u8, flag, Some(ForwardingMod::FeeTooLow));
		do_test_htlc_interception_flags(flag as u8, flag, Some(ForwardingMod::CLTVBelowConfig));
	}
}

#[test]
fn test_htlc_bad_no_chan() {
	// Test that setting the CLTV below the hard-coded minimum fails whether we're intercepting for
	// a channel or not.
	for flag in ALL_FLAGS {
		do_test_htlc_interception_flags(flag as u8, flag, Some(ForwardingMod::CLTVBelowMin));
	}
}
