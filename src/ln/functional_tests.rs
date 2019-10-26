//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use chain::transaction::OutPoint;
use chain::chaininterface::{ChainListener, ChainWatchInterface, ChainWatchInterfaceUtil};
use chain::keysinterface::{KeysInterface, SpendableOutputDescriptor, KeysManager};
use chain::keysinterface;
use ln::channel::{COMMITMENT_TX_BASE_WEIGHT, COMMITMENT_TX_WEIGHT_PER_HTLC};
use ln::channelmanager::{ChannelManager,ChannelManagerReadArgs,HTLCForwardInfo,RAACommitmentOrder, PaymentPreimage, PaymentHash, BREAKDOWN_TIMEOUT};
use ln::channelmonitor::{ChannelMonitor, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ManyChannelMonitor, ANTI_REORG_DELAY};
use ln::channel::{ACCEPTED_HTLC_SCRIPT_WEIGHT, OFFERED_HTLC_SCRIPT_WEIGHT, Channel, ChannelError};
use ln::onion_utils;
use ln::router::{Route, RouteHop};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler,HTLCFailChannelUpdate, LocalFeatures, ErrorAction};
use util::test_utils;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::ser::{Writeable, ReadableArgs};
use util::config::UserConfig;
use util::logger::Logger;

use bitcoin::util::hash::BitcoinHash;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::util::bip143;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey, ExtendedPrivKey};
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, SigHashType, OutPoint as BitcoinOutPoint};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;

use secp256k1::{Secp256k1, Message};
use secp256k1::key::{PublicKey,SecretKey};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::default::Default;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::mem;

use rand::{thread_rng, Rng};

use ln::functional_test_utils::*;

#[test]
fn test_insane_channel_opens() {
	// Stand up a network of 2 nodes
	let nodes = create_network(2, &[None, None]);

	// Instantiate channel parameters where we push the maximum msats given our
	// funding satoshis
	let channel_value_sat = 31337; // same as funding satoshis
	let channel_reserve_satoshis = Channel::get_our_channel_reserve_satoshis(channel_value_sat);
	let push_msat = (channel_value_sat - channel_reserve_satoshis) * 1000;

	// Have node0 initiate a channel to node1 with aforementioned parameters
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_sat, push_msat, 42).unwrap();

	// Extract the channel open message from node0 to node1
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	// Test helper that asserts we get the correct error string given a mutator
	// that supposedly makes the channel open message insane
	let insane_open_helper = |expected_error_str, message_mutator: fn(msgs::OpenChannel) -> msgs::OpenChannel| {
		match nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), LocalFeatures::new(), &message_mutator(open_channel_message.clone())) {
			Err(msgs::HandleError{ err: error_str, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) => {
				assert_eq!(error_str, expected_error_str, "unexpected HandleError string (expected `{}`, actual `{}`)", expected_error_str, error_str)
			},
			Err(msgs::HandleError{..}) => {panic!("unexpected HandleError action")},
			_ => panic!("insane OpenChannel message was somehow Ok"),
		}
	};

	use ln::channel::MAX_FUNDING_SATOSHIS;
	use ln::channelmanager::MAX_LOCAL_BREAKDOWN_TIMEOUT;

	// Test all mutations that would make the channel open message insane
	insane_open_helper("funding value > 2^24", |mut msg| { msg.funding_satoshis = MAX_FUNDING_SATOSHIS; msg });

	insane_open_helper("Bogus channel_reserve_satoshis", |mut msg| { msg.channel_reserve_satoshis = msg.funding_satoshis + 1; msg });

	insane_open_helper("push_msat larger than funding value", |mut msg| { msg.push_msat = (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 + 1; msg });

	insane_open_helper("Peer never wants payout outputs?", |mut msg| { msg.dust_limit_satoshis = msg.funding_satoshis + 1 ; msg });

	insane_open_helper("Bogus; channel reserve is less than dust limit", |mut msg| { msg.dust_limit_satoshis = msg.channel_reserve_satoshis + 1; msg });

	insane_open_helper("Minimum htlc value is full channel value", |mut msg| { msg.htlc_minimum_msat = (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000; msg });

	insane_open_helper("They wanted our payments to be delayed by a needlessly long period", |mut msg| { msg.to_self_delay = MAX_LOCAL_BREAKDOWN_TIMEOUT + 1; msg });

	insane_open_helper("0 max_accpted_htlcs makes for a useless channel", |mut msg| { msg.max_accepted_htlcs = 0; msg });

	insane_open_helper("max_accpted_htlcs > 483", |mut msg| { msg.max_accepted_htlcs = 484; msg });
}

#[test]
fn test_async_inbound_update_fee() {
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

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
	nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[1].node.send_payment(nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap(), our_payment_hash).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap(); // (2)
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	// deliver(1), generate (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// nodes[1] is awaiting nodes[0] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap(); // deliver (2)
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_update.update_add_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fulfill_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_malformed_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fee.is_none()); // (4)
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap(); // deliver (3)
	let as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_update.update_add_htlcs.is_empty()); // (5)
	assert!(as_update.update_fulfill_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_malformed_htlcs.is_empty()); // (5)
	assert!(as_update.update_fee.is_none()); // (5)
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed).unwrap(); // deliver (4)
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// only (6) so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update.commitment_signed).unwrap(); // deliver (5)
	let bs_second_revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_2 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PendingHTLCsForwardable {..} => {}, // If we actually processed we'd receive the payment
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke).unwrap(); // deliver (6)
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_unordered_raa() {
	// Just the intro to the previous test followed by an out-of-order RAA (which caused a
	// crash in an earlier version of the update_fee patch)
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	// First nodes[0] generates an update_fee
	nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let update_msg = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, .. }, .. } => {
			update_fee.as_ref()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[1].node.send_payment(nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap(), our_payment_hash).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap(); // (2)
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg).unwrap(); // deliver (2)
	check_added_monitors!(nodes[1], 1);

	// We can't continue, sadly, because our (1) now has a bogus signature
}

#[test]
fn test_multi_flight_update_fee() {
	let nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

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
	let initial_feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, initial_feerate + 20).unwrap();
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
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg_1).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed_1).unwrap();
	let (bs_revoke_msg, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// nodes[0] is awaiting a revoke from nodes[1] before it will create a new commitment
	// transaction:
	nodes[0].node.update_fee(channel_id, initial_feerate + 40).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Create the (3) update_fee message that nodes[0] will generate before it does...
	let mut update_msg_2 = msgs::UpdateFee {
		channel_id: update_msg_1.channel_id.clone(),
		feerate_per_kw: (initial_feerate + 30) as u32,
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2).unwrap();

	update_msg_2.feerate_per_kw = (initial_feerate + 40) as u32;
	// Deliver (3)
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2).unwrap();

	// Deliver (1), generating (3) and (4)
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_msg).unwrap();
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
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed).unwrap();
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Delever (4)
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update.commitment_signed).unwrap();
	let (bs_second_revoke, bs_second_commitment) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment).unwrap();
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_vanilla() {
	let nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+25).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_that_funder_cannot_afford() {
	let nodes = create_network(2, &[None, None]);
	let channel_value = 1888;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 700000, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

	let feerate = 260;
	nodes[0].node.update_fee(channel_id, feerate).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg.update_fee.unwrap()).unwrap();

	commitment_signed_dance!(nodes[1], nodes[0], update_msg.commitment_signed, false);

	//Confirm that the new fee based on the last local commitment txn is what we expected based on the feerate of 260 set above.
	//This value results in a fee that is exactly what the funder can afford (277 sat + 1000 sat channel reserve)
	{
		let chan_lock = nodes[1].node.channel_state.lock().unwrap();
		let chan = chan_lock.by_id.get(&channel_id).unwrap();

		//We made sure neither party's funds are below the dust limit so -2 non-HTLC txns from number of outputs
		let num_htlcs = chan.last_local_commitment_txn[0].output.len() - 2;
		let total_fee: u64 = feerate * (COMMITMENT_TX_BASE_WEIGHT + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;
		let mut actual_fee = chan.last_local_commitment_txn[0].output.iter().fold(0, |acc, output| acc + output.value);
		actual_fee = channel_value - actual_fee;
		assert_eq!(total_fee, actual_fee);
	} //drop the mutex

	//Add 2 to the previous fee rate to the final fee increases by 1 (with no HTLCs the fee is essentially
	//fee_rate*(724/1000) so the increment of 1*0.724 is rounded back down)
	nodes[0].node.update_fee(channel_id, feerate+2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let update2_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update2_msg.update_fee.unwrap()).unwrap();

	//While producing the commitment_signed response after handling a received update_fee request the
	//check to see if the funder, who sent the update_fee request, can afford the new fee (funder_balance >= fee+channel_reserve)
	//Should produce and error.
	let err = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &update2_msg.commitment_signed).unwrap_err();

	assert!(match err.err {
		"Funding remote cannot afford proposed new fee" => true,
		_ => false,
	});

	//clear the message we could not handle
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_update_fee_with_fundee_update_add_htlc() {
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let channel_id = chan.2;

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	let route = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 800000, TEST_FINAL_CLTV).unwrap();

	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[1]);

	// nothing happens since node[1] is in AwaitingRemoteRevoke
	nodes[1].node.send_payment(route, our_payment_hash).unwrap();
	{
		let mut added_monitors = nodes[0].chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 0);
		added_monitors.clear();
	}
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	// node[1] has nothing to do

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
	check_added_monitors!(nodes[1], 1);
	// AwaitingRemoteRevoke ends here

	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(commitment_update.update_add_htlcs.len(), 1);
	assert_eq!(commitment_update.update_fulfill_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_malformed_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fee.is_none(), true);

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &commitment_update.update_add_htlcs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let (revoke, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke).unwrap();
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke).unwrap();
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[0]);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { .. } => { },
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[1], &vec!(&nodes[0])[..], our_payment_preimage);

	send_payment(&nodes[1], &vec!(&nodes[0])[..], 800000);
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 800000);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
}

#[test]
fn test_update_fee() {
	let nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
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
	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

	// Generate (2) and (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
	let (revoke_msg, commitment_signed_0) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// Deliver (2):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Create and deliver (4)...
	nodes[0].node.update_fee(channel_id, feerate+30).unwrap();
	check_added_monitors!(nodes[0], 1);
	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	// ... creating (5)
	let revoke_msg = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Handle (3), creating (6):
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed_0).unwrap();
	check_added_monitors!(nodes[0], 1);
	let revoke_msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Deliver (5):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Deliver (6), creating (7):
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg_0).unwrap();
	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(commitment_update.update_add_htlcs.is_empty());
	assert!(commitment_update.update_fulfill_htlcs.is_empty());
	assert!(commitment_update.update_fail_htlcs.is_empty());
	assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
	assert!(commitment_update.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	// Deliver (7)
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(get_feerate!(nodes[0], channel_id), feerate + 30);
	assert_eq!(get_feerate!(nodes[1], channel_id), feerate + 30);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
}

#[test]
fn pre_funding_lock_shutdown_test() {
	// Test sending a shutdown prior to funding_locked after funding generation
	let nodes = create_network(2, &[None, None]);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0, LocalFeatures::new(), LocalFeatures::new());
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&tx; 1], &[1; 1]);
	nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&tx; 1], &[1; 1]);

	nodes[0].node.close_channel(&OutPoint::new(tx.txid(), 0).to_channel_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
}

#[test]
fn updates_shutdown_wait() {
	// Test sending a shutdown with outstanding updates pending
	let mut nodes = create_network(3, &[None, None, None]);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());
	let route_1 = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
	let route_2 = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[0].node.close_channel(&chan_1.2).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	if let Err(APIError::ChannelUnavailable {..}) = nodes[0].node.send_payment(route_1, payment_hash) {}
	else { panic!("New sends should fail!") };
	if let Err(APIError::ChannelUnavailable {..}) = nodes[1].node.send_payment(route_2, payment_hash) {}
	else { panic!("New sends should fail!") };

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn htlc_fail_async_shutdown() {
	// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
	let mut nodes = create_network(3, &[None, None, None]);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());

	nodes[1].node.close_channel(&chan_1.2).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false);

	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fulfill_htlcs.is_empty());
	assert_eq!(updates_2.update_fail_htlcs.len(), 1);
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fail_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, .. } => {
			assert_eq!(our_payment_hash, *payment_hash);
			assert!(!rejected_by_dest);
		},
		_ => panic!("Unexpected event"),
	}

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let node_0_closing_signed = match msg_events[0] {
		MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	match msg_events[1] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_1.0.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

fn do_test_shutdown_rebroadcast(recv_count: u8) {
	// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
	// messages delivered prior to disconnect
	let nodes = create_network(3, &[None, None, None]);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[1].node.close_channel(&chan_1.2).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	if recv_count > 0 {
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		if recv_count > 1 {
			nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	let node_0_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
	let node_1_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_reestablish).unwrap();
	let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	assert!(node_1_shutdown == node_1_2nd_shutdown);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_reestablish).unwrap();
	let node_0_2nd_shutdown = if recv_count > 0 {
		let node_0_2nd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown).unwrap();
		node_0_2nd_shutdown
	} else {
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown).unwrap();
		get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id())
	};
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_2nd_shutdown).unwrap();

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	if recv_count > 0 {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		assert!(node_1_closing_signed.is_some());
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	let node_0_2nd_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
	if recv_count == 0 {
		// If all closing_signeds weren't delivered we can just resume where we left off...
		let node_1_2nd_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish).unwrap();
		let node_0_3rd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		assert!(node_0_2nd_shutdown == node_0_3rd_shutdown);

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish).unwrap();
		let node_1_3rd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_3rd_shutdown).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_3rd_shutdown).unwrap();
		let node_0_2nd_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		assert!(node_0_closing_signed == node_0_2nd_closing_signed);

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());
	} else {
		// If one node, however, received + responded with an identical closing_signed we end
		// up erroring and node[0] will try to broadcast its own latest commitment transaction.
		// There isn't really anything better we can do simply, but in the future we might
		// explore storing a set of recently-closed channels that got disconnected during
		// closing_signed and avoiding broadcasting local commitment txn for some timeout to
		// give our counterparty enough time to (potentially) broadcast a cooperative closing
		// transaction.
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		if let Err(msgs::HandleError{action: Some(msgs::ErrorAction::SendErrorMessage{msg}), ..}) =
				nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish) {
			nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msg);
			let msgs::ErrorMessage {ref channel_id, ..} = msg;
			assert_eq!(*channel_id, chan_1.2);
		} else { panic!("Needed SendErrorMessage close"); }

		// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
		// checks it, but in this case nodes[0] didn't ever get a chance to receive a
		// closing_signed so we do it ourselves
		check_closed_broadcast!(nodes[0]);
	}

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn test_shutdown_rebroadcast() {
	do_test_shutdown_rebroadcast(0);
	do_test_shutdown_rebroadcast(1);
	do_test_shutdown_rebroadcast(2);
}

#[test]
fn fake_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that payments get routed and transactions broadcast in semi-reasonable ways.
	let nodes = create_network(4, &[None, None, None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3, LocalFeatures::new(), LocalFeatures::new());

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
	let chan_4 = create_announced_chan_between_nodes(&nodes, 1, 3, LocalFeatures::new(), LocalFeatures::new());

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
		short_channel_id: chan_2.0.contents.short_channel_id,
		fee_msat: 0,
		cltv_expiry_delta: chan_3.0.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		fee_msat: 0,
		cltv_expiry_delta: chan_4.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
	});
	hops[1].fee_msat = chan_4.1.contents.fee_base_msat as u64 + chan_4.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.0.contents.fee_base_msat as u64 + chan_3.0.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_preimage_1 = send_along_route(&nodes[1], Route { hops }, &vec!(&nodes[2], &nodes[3], &nodes[1])[..], 1000000).0;

	let mut hops = Vec::with_capacity(3);
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		fee_msat: 0,
		cltv_expiry_delta: chan_3.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[2].node.get_our_node_id(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		fee_msat: 0,
		cltv_expiry_delta: chan_2.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		short_channel_id: chan_2.0.contents.short_channel_id,
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
	});
	hops[1].fee_msat = chan_2.1.contents.fee_base_msat as u64 + chan_2.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.1.contents.fee_base_msat as u64 + chan_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_hash_2 = send_along_route(&nodes[1], Route { hops }, &vec!(&nodes[3], &nodes[2], &nodes[1])[..], 1000000).1;

	// Claim the rebalances...
	fail_payment(&nodes[1], &vec!(&nodes[3], &nodes[2], &nodes[1])[..], payment_hash_2);
	claim_payment(&nodes[1], &vec!(&nodes[2], &nodes[3], &nodes[1])[..], payment_preimage_1);

	// Add a duplicate new channel from 2 to 4
	let chan_5 = create_announced_chan_between_nodes(&nodes, 1, 3, LocalFeatures::new(), LocalFeatures::new());

	// Send some payments across both channels
	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
	let payment_preimage_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;

	route_over_limit(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000);

	//TODO: Test that routes work again here as we've been notified that the channel is full

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_3);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_4);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_5);

	// Close down the channels...
	close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, false);
	close_channel(&nodes[2], &nodes[3], &chan_3.2, chan_3.3, true);
	close_channel(&nodes[1], &nodes[3], &chan_4.2, chan_4.3, false);
	close_channel(&nodes[1], &nodes[3], &chan_5.2, chan_5.3, false);
}

#[test]
fn holding_cell_htlc_counting() {
	// Tests that HTLCs in the holding cell count towards the pending HTLC limits on outbound HTLCs
	// to ensure we don't end up with HTLCs sitting around in our holding cell for several
	// commitment dance rounds.
	let mut nodes = create_network(3, &[None, None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let mut payments = Vec::new();
	for _ in 0..::ln::channel::OUR_MAX_HTLCS {
		let route = nodes[1].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 100000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
		nodes[1].node.send_payment(route, payment_hash).unwrap();
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
	let route = nodes[1].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 100000, TEST_FINAL_CLTV).unwrap();
	let (_, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	if let APIError::ChannelUnavailable { err } = nodes[1].node.send_payment(route, payment_hash_1).unwrap_err() {
		assert_eq!(err, "Cannot push more than their max accepted HTLCs");
	} else { panic!("Unexpected event"); }

	// This should also be true if we try to forward a payment.
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 100000, TEST_FINAL_CLTV).unwrap();
	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
	// fails), the second will process the resulting failure and fail the HTLC backward.
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_updates.update_fail_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], bs_fail_updates.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_2.0.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { payment_hash, rejected_by_dest, .. } => {
			assert_eq!(payment_hash, payment_hash_2);
			assert!(!rejected_by_dest);
		},
		_ => panic!("Unexpected event"),
	}

	// Now forward all the pending HTLCs and claim them back
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &initial_payment_event.msgs[0]).unwrap();
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &initial_payment_event.commitment_msg).unwrap();
	check_added_monitors!(nodes[2], 1);

	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
	check_added_monitors!(nodes[1], 1);
	let as_updates = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	for ref update in as_updates.update_add_htlcs.iter() {
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), update).unwrap();
	}
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[2], 1);
	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let as_final_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_final_raa).unwrap();
	check_added_monitors!(nodes[2], 1);

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), payments.len());
	for (event, &(_, ref hash)) in events.iter().zip(payments.iter()) {
		match event {
			&Event::PaymentReceived { ref payment_hash, .. } => {
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
	let mut nodes = create_network(6, &[None, None, None, None, None, None]);

	// Create some initial channels to route via 3 to 4/5 from 0/1/2
	create_announced_chan_between_nodes(&nodes, 0, 3, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 1, 3, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 2, 3, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 3, 4, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 3, 5, LocalFeatures::new(), LocalFeatures::new());

	let (payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], 1000000);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[1], &vec!(&nodes[3])[..], 1000000).0, payment_preimage);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], 1000000).0, payment_preimage);

	claim_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], payment_preimage);
	fail_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], payment_hash);
	claim_payment(&nodes[1], &vec!(&nodes[3])[..], payment_preimage);
}

fn do_channel_reserve_test(test_recv: bool) {
	use ln::msgs::HandleError;

	let mut nodes = create_network(3, &[None, None, None]);
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1900, 1001, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1900, 1001, LocalFeatures::new(), LocalFeatures::new());

	let mut stat01 = get_channel_value_stat!(nodes[0], chan_1.2);
	let mut stat11 = get_channel_value_stat!(nodes[1], chan_1.2);

	let mut stat12 = get_channel_value_stat!(nodes[1], chan_2.2);
	let mut stat22 = get_channel_value_stat!(nodes[2], chan_2.2);

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let route = nodes[0].router.get_route(&nodes.last().unwrap().node.get_our_node_id(), None, &Vec::new(), $recv_value, TEST_FINAL_CLTV).unwrap();
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
			(route, payment_hash, payment_preimage)
		}}
	};

	macro_rules! expect_forward {
		($node: expr) => {{
			let mut events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			check_added_monitors!($node, 1);
			let payment_event = SendEvent::from_event(events.remove(0));
			payment_event
		}}
	}

	let feemsat = 239; // somehow we know?
	let total_fee_msat = (nodes.len() - 2) as u64 * 239;

	let recv_value_0 = stat01.their_max_htlc_value_in_flight_msat - total_fee_msat;

	// attempt to send amt_msat > their_max_htlc_value_in_flight_msat
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_0 + 1);
		assert!(route.hops.iter().rev().skip(1).all(|h| h.fee_msat == feemsat));
		let err = nodes[0].node.send_payment(route, our_payment_hash).err().unwrap();
		match err {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over the max HTLC value in flight our peer will accept"),
			_ => panic!("Unknown error variants"),
		}
	}

	let mut htlc_id = 0;
	// channel reserve is bigger than their_max_htlc_value_in_flight_msat so loop to deplete
	// nodes[0]'s wealth
	loop {
		let amt_msat = recv_value_0 + total_fee_msat;
		if stat01.value_to_self_msat - amt_msat < stat01.channel_reserve_msat {
			break;
		}
		send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], recv_value_0);
		htlc_id += 1;

		let (stat01_, stat11_, stat12_, stat22_) = (
			get_channel_value_stat!(nodes[0], chan_1.2),
			get_channel_value_stat!(nodes[1], chan_1.2),
			get_channel_value_stat!(nodes[1], chan_2.2),
			get_channel_value_stat!(nodes[2], chan_2.2),
		);

		assert_eq!(stat01_.value_to_self_msat, stat01.value_to_self_msat - amt_msat);
		assert_eq!(stat11_.value_to_self_msat, stat11.value_to_self_msat + amt_msat);
		assert_eq!(stat12_.value_to_self_msat, stat12.value_to_self_msat - (amt_msat - feemsat));
		assert_eq!(stat22_.value_to_self_msat, stat22.value_to_self_msat + (amt_msat - feemsat));
		stat01 = stat01_; stat11 = stat11_; stat12 = stat12_; stat22 = stat22_;
	}

	{
		let recv_value = stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat;
		// attempt to get channel_reserve violation
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value + 1);
		let err = nodes[0].node.send_payment(route.clone(), our_payment_hash).err().unwrap();
		match err {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over their reserve value"),
			_ => panic!("Unknown error variants"),
		}
	}

	// adding pending output
	let recv_value_1 = (stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat)/2;
	let amt_msat_1 = recv_value_1 + total_fee_msat;

	let (route_1, our_payment_hash_1, our_payment_preimage_1) = get_route_and_payment_hash!(recv_value_1);
	let payment_event_1 = {
		nodes[0].node.send_payment(route_1, our_payment_hash_1).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]).unwrap();

	// channel reserve test with htlc pending output > 0
	let recv_value_2 = stat01.value_to_self_msat - amt_msat_1 - stat01.channel_reserve_msat - total_fee_msat;
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);
		match nodes[0].node.send_payment(route, our_payment_hash).err().unwrap() {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over their reserve value"),
			_ => panic!("Unknown error variants"),
		}
	}

	{
		// test channel_reserve test on nodes[1] side
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);

		// Need to manually create update_add_htlc message to go around the channel reserve check in send_htlc()
		let secp_ctx = Secp256k1::new();
		let session_priv = SecretKey::from_slice(&{
			let mut session_key = [0; 32];
			let mut rng = thread_rng();
			rng.fill_bytes(&mut session_key);
			session_key
		}).expect("RNG is bad!");

		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route, &session_priv).unwrap();
		let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height).unwrap();
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &our_payment_hash);
		let msg = msgs::UpdateAddHTLC {
			channel_id: chan_1.2,
			htlc_id,
			amount_msat: htlc_msat,
			payment_hash: our_payment_hash,
			cltv_expiry: htlc_cltv,
			onion_routing_packet: onion_packet,
		};

		if test_recv {
			let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg).err().unwrap();
			match err {
				HandleError{err, .. } => assert_eq!(err, "Remote HTLC add would put them over their reserve value"),
			}
			// If we send a garbage message, the channel should get closed, making the rest of this test case fail.
			assert_eq!(nodes[1].node.list_channels().len(), 1);
			assert_eq!(nodes[1].node.list_channels().len(), 1);
			check_closed_broadcast!(nodes[1]);
			return;
		}
	}

	// split the rest to test holding cell
	let recv_value_21 = recv_value_2/2;
	let recv_value_22 = recv_value_2 - recv_value_21 - total_fee_msat;
	{
		let stat = get_channel_value_stat!(nodes[0], chan_1.2);
		assert_eq!(stat.value_to_self_msat - (stat.pending_outbound_htlcs_amount_msat + recv_value_21 + recv_value_22 + total_fee_msat + total_fee_msat), stat.channel_reserve_msat);
	}

	// now see if they go through on both sides
	let (route_21, our_payment_hash_21, our_payment_preimage_21) = get_route_and_payment_hash!(recv_value_21);
	// but this will stuck in the holding cell
	nodes[0].node.send_payment(route_21, our_payment_hash_21).unwrap();
	check_added_monitors!(nodes[0], 0);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0);

	// test with outbound holding cell amount > 0
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_22+1);
		match nodes[0].node.send_payment(route, our_payment_hash).err().unwrap() {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over their reserve value"),
			_ => panic!("Unknown error variants"),
		}
	}

	let (route_22, our_payment_hash_22, our_payment_preimage_22) = get_route_and_payment_hash!(recv_value_22);
	// this will also stuck in the holding cell
	nodes[0].node.send_payment(route_22, our_payment_hash_22).unwrap();
	check_added_monitors!(nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// flush the pending htlc
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event_1.commitment_msg).unwrap();
	let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
	check_added_monitors!(nodes[0], 1);
	let commitment_update_2 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_commitment_signed).unwrap();
	let bs_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_11 = expect_forward!(nodes[1]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_11.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[2], nodes[1], payment_event_11.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[2]);
	expect_payment_received!(nodes[2], our_payment_hash_1, recv_value_1);

	// flush the htlcs in the holding cell
	assert_eq!(commitment_update_2.update_add_htlcs.len(), 2);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[0]).unwrap();
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[1]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], &commitment_update_2.commitment_signed, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_3 = expect_forward!(nodes[1]);
	assert_eq!(payment_event_3.msgs.len(), 2);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[0]).unwrap();
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[1]).unwrap();

	commitment_signed_dance!(nodes[2], nodes[1], &payment_event_3.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(our_payment_hash_21, *payment_hash);
			assert_eq!(recv_value_21, amt);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(our_payment_hash_22, *payment_hash);
			assert_eq!(recv_value_22, amt);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_1);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_21);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_22);

	let expected_value_to_self = stat01.value_to_self_msat - (recv_value_1 + total_fee_msat) - (recv_value_21 + total_fee_msat) - (recv_value_22 + total_fee_msat);
	let stat0 = get_channel_value_stat!(nodes[0], chan_1.2);
	assert_eq!(stat0.value_to_self_msat, expected_value_to_self);
	assert_eq!(stat0.value_to_self_msat, stat0.channel_reserve_msat);

	let stat2 = get_channel_value_stat!(nodes[2], chan_2.2);
	assert_eq!(stat2.value_to_self_msat, stat22.value_to_self_msat + recv_value_1 + recv_value_21 + recv_value_22);
}

#[test]
fn channel_reserve_test() {
	do_channel_reserve_test(false);
	do_channel_reserve_test(true);
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
	let mut nodes = create_network(2, &[None, None]);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let b_chan_values = get_channel_value_stat!(nodes[1], chan_1.2);
	// Route the first two HTLCs.
	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], b_chan_values.channel_reserve_msat - b_chan_values.value_to_self_msat - 10000);
	let (payment_preimage_2, _) = route_payment(&nodes[0], &[&nodes[1]], 20000);

	// Start routing the third HTLC (this is just used to get everyone in the right state).
	let (payment_preimage_3, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);
	let send_1 = {
		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
		nodes[0].node.send_payment(route, payment_hash_3).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	// Now claim both of the first two HTLCs on B's end, putting B in AwaitingRAA and generating an
	// initial fulfill/CS.
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);
	let bs_removes = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	// This claim goes in B's holding cell, allowing us to have a pending B->A RAA which does not
	// remove the second HTLC when we send the HTLC back from B to A.
	assert!(nodes[1].node.claim_funds(payment_preimage_2));
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_removes.update_fulfill_htlcs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_removes.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent!(nodes[0], payment_preimage_1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_1.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_1.commitment_msg).unwrap();
	check_added_monitors!(nodes[1], 1);
	// B is already AwaitingRAA, so cant generate a CS here
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	// The second HTLCis removed, but as A is in AwaitingRAA it can't generate a CS here, so the
	// RAA that B generated above doesn't fully resolve the second HTLC from A's point of view.
	// However, the RAA A generates here *does* fully resolve the HTLC from B's point of view (as A
	// can no longer broadcast a commitment transaction with it and B has the preimage so can go
	// on-chain as necessary).
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_cs.update_fulfill_htlcs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent!(nodes[0], payment_preimage_2);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_3, 100000);

	// Note that as this RAA was generated before the delivery of the update_fulfill it shouldn't
	// resolve the second HTLC from A's point of view.
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// Now that B doesn't have the second RAA anymore, but A still does, send a payment from B back
	// to A to ensure that A doesn't count the almost-removed HTLC in update_add processing.
	let (payment_preimage_4, payment_hash_4) = get_payment_preimage_hash!(nodes[1]);
	let send_2 = {
		let route = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &[], 10000, TEST_FINAL_CLTV).unwrap();
		nodes[1].node.send_payment(route, payment_hash_4).unwrap();
		check_added_monitors!(nodes[1], 1);
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_2.msgs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_2.commitment_msg).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Now just resolve all the outstanding messages/HTLCs for completeness...

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_received!(nodes[0], payment_hash_4, 10000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_4);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);
}

#[test]
fn channel_monitor_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that ChannelMonitor is able to recover from various states.
	let nodes = create_network(5, &[None, None, None, None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3, LocalFeatures::new(), LocalFeatures::new());
	let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);

	// Simple case with no pending HTLCs:
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), true);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, HTLCType::NONE);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
		test_txn_broadcast(&nodes[0], &chan_1, None, HTLCType::NONE);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	// One pending HTLC is discarded by the force-close:
	let payment_preimage_1 = route_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 3000000).0;

	// Simple case of one pending HTLC to HTLC-Timeout
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), true);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
		test_txn_broadcast(&nodes[2], &chan_2, None, HTLCType::NONE);
	}
	get_announce_close_broadcast_events(&nodes, 1, 2);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
	assert_eq!(nodes[2].node.list_channels().len(), 1);

	macro_rules! claim_funds {
		($node: expr, $prev_node: expr, $preimage: expr) => {
			{
				assert!($node.node.claim_funds($preimage));
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
	nodes[2].node.peer_disconnected(&nodes[3].node.get_our_node_id(), true);
	{
		let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::TIMEOUT);

		// Claim the payment on nodes[3], giving it knowledge of the preimage
		claim_funds!(nodes[3], nodes[2], payment_preimage_1);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[3].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 1);

		check_preimage_claim(&nodes[3], &node_txn);
	}
	get_announce_close_broadcast_events(&nodes, 2, 3);
	assert_eq!(nodes[2].node.list_channels().len(), 0);
	assert_eq!(nodes[3].node.list_channels().len(), 1);

	{ // Cheat and reset nodes[4]'s height to 1
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[4].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![] }, 1);
	}

	assert_eq!(nodes[3].node.latest_block_height.load(Ordering::Acquire), 1);
	assert_eq!(nodes[4].node.latest_block_height.load(Ordering::Acquire), 1);
	// One pending HTLC to time out:
	let payment_preimage_2 = route_payment(&nodes[3], &vec!(&nodes[4])[..], 3000000).0;
	// CLTV expires at TEST_FINAL_CLTV + 1 (current height) + 1 (added in send_payment for
	// buffer space).

	{
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[3].chain_monitor.block_connected_checked(&header, 2, &Vec::new()[..], &[0; 0]);
		for i in 3..TEST_FINAL_CLTV + 2 + LATENCY_GRACE_PERIOD_BLOCKS + 1 {
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[3].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
		}

		let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, HTLCType::TIMEOUT);

		// Claim the payment on nodes[4], giving it knowledge of the preimage
		claim_funds!(nodes[4], nodes[3], payment_preimage_2);

		header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[4].chain_monitor.block_connected_checked(&header, 2, &Vec::new()[..], &[0; 0]);
		for i in 3..TEST_FINAL_CLTV + 2 - CLTV_CLAIM_BUFFER + 1 {
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
		}

		test_txn_broadcast(&nodes[4], &chan_4, None, HTLCType::SUCCESS);

		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[4].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, TEST_FINAL_CLTV - 5);

		check_preimage_claim(&nodes[4], &node_txn);
	}
	get_announce_close_broadcast_events(&nodes, 3, 4);
	assert_eq!(nodes[3].node.list_channels().len(), 0);
	assert_eq!(nodes[4].node.list_channels().len(), 0);
}

#[test]
fn test_justice_tx() {
	// Test justice txn built on revoked HTLC-Success tx, against both sides

	let mut alice_config = UserConfig::new();
	alice_config.channel_options.announced_channel = true;
	alice_config.peer_channel_config_limits.force_announced_channel_preference = false;
	alice_config.own_channel_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = UserConfig::new();
	bob_config.channel_options.announced_channel = true;
	bob_config.peer_channel_config_limits.force_announced_channel_preference = false;
	bob_config.own_channel_config.our_to_self_delay = 6 * 24 * 3;
	let nodes = create_network(2, &[Some(alice_config), Some(bob_config)]);
	// Create some new channels:
	let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// A pending HTLC which will be revoked:
	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from nodes[0]
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn.len(), 2); // First commitment tx, then HTLC tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_5.3.txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to 0 are present
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);

	{
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		{
			let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 3);
			assert_eq!(node_txn.pop().unwrap(), node_txn[0]); // An outpoint registration will result in a 2nd block_connected
			assert_eq!(node_txn[0].input.len(), 2); // We should claim the revoked output and the HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0].clone());
			node_txn.swap_remove(0);
		}
		test_txn_broadcast(&nodes[1], &chan_5, None, HTLCType::NONE);

		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let node_txn = test_txn_broadcast(&nodes[0], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::TIMEOUT);
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[1].clone()] }, 1);
		test_revoked_htlc_claim_txn_broadcast(&nodes[1], node_txn[1].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);

	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// We test justice_tx build by A on B's revoked HTLC-Success tx
	// Create some new channels:
	let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// A pending HTLC which will be revoked:
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from B
	let revoked_local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn.len(), 1); // Only commitment tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_6.3.txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to A are present
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_4);
	{
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		{
			let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 3);
			assert_eq!(node_txn.pop().unwrap(), node_txn[0]); // An outpoint registration will result in a 2nd block_connected
			assert_eq!(node_txn[0].input.len(), 1); // We claim the received HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0].clone());
			node_txn.swap_remove(0);
		}
		test_txn_broadcast(&nodes[0], &chan_6, None, HTLCType::NONE);

		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let node_txn = test_txn_broadcast(&nodes[1], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::SUCCESS);
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[1].clone()] }, 1);
		test_revoked_htlc_claim_txn_broadcast(&nodes[0], node_txn[1].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn revoked_output_claim() {
	// Simple test to ensure a node will claim a revoked output when a stale remote commitment
	// transaction is broadcast by its counterparty
	let nodes = create_network(2, &[None, None]);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn.len(), 1);
	// Only output is the full channel value back to nodes[0]:
	assert_eq!(revoked_local_txn[0].output.len(), 1);
	// Send a payment through, updating everyone's latest commitment txn
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 5000000);

	// Inform nodes[1] that nodes[0] broadcast a stale tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 3); // nodes[1] will broadcast justice tx twice, and its own local state once

	assert_eq!(node_txn[0], node_txn[2]);

	check_spends!(node_txn[0], revoked_local_txn[0].clone());
	check_spends!(node_txn[1], chan_1.3.clone());

	// Inform nodes[0] that a watchtower cheated on its behalf, so it will force-close the chan
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	get_announce_close_broadcast_events(&nodes, 0, 1);
}

#[test]
fn claim_htlc_outputs_shared_tx() {
	// Node revoked old state, htlcs haven't time out yet, claim them in shared justice tx
	let nodes = create_network(2, &[None, None]);

	// Create some new channel:
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx
	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let (_payment_preimage_2, payment_hash_2) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn.len(), 2); // commitment tx + 1 HTLC-Timeout tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	check_spends!(revoked_local_txn[1], revoked_local_txn[0].clone());

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

	{
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 1, true, header.bitcoin_hash());

		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, payment_hash_2);
			},
			_ => panic!("Unexpected event"),
		}

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 4);

		assert_eq!(node_txn[0].input.len(), 3); // Claim the revoked output + both revoked HTLC outputs
		check_spends!(node_txn[0], revoked_local_txn[0].clone());

		assert_eq!(node_txn[0], node_txn[3]); // justice tx is duplicated due to block re-scanning

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[1].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[2].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		// Next nodes[1] broadcasts its current local tx state:
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[1].input[0].previous_output.txid, chan_1.3.txid()); //Spending funding tx unique txouput, tx broadcasted by ChannelManager

		assert_eq!(node_txn[2].input.len(), 1);
		let witness_script = node_txn[2].clone().input[0].witness.pop().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		assert_eq!(node_txn[2].input[0].previous_output.txid, node_txn[1].txid());
		assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[0].previous_output.txid);
		assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[1].previous_output.txid);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn claim_htlc_outputs_single_tx() {
	// Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
	let nodes = create_network(2, &[None, None]);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
	// time as two different claim transactions as we're gonna to timeout htlc with given a high current height
	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let (_payment_preimage_2, payment_hash_2) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

	{
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);
		connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 200, true, header.bitcoin_hash());

		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, payment_hash_2);
			},
			_ => panic!("Unexpected event"),
		}

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 22); // ChannelManager : 2, ChannelMontitor: 8 (1 standard revoked output, 2 revocation htlc tx, 1 local commitment tx + 1 htlc timeout tx) * 2 (block-rescan) + 5 * (1 local commitment tx + 1 htlc timeout tx)

		assert_eq!(node_txn[0], node_txn[7]);
		assert_eq!(node_txn[1], node_txn[8]);
		assert_eq!(node_txn[2], node_txn[9]);
		assert_eq!(node_txn[3], node_txn[10]);
		assert_eq!(node_txn[4], node_txn[11]);
		assert_eq!(node_txn[3], node_txn[5]); //local commitment tx + htlc timeout tx broadcasted by ChannelManger
		assert_eq!(node_txn[4], node_txn[6]);

		for i in 12..22 {
			if i % 2 == 0 { assert_eq!(node_txn[3], node_txn[i]); } else { assert_eq!(node_txn[4], node_txn[i]); }
		}

		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);

		fn get_txout(out_point: &BitcoinOutPoint, tx: &Transaction) -> Option<TxOut> {
			if out_point.txid == tx.txid() {
				tx.output.get(out_point.vout as usize).cloned()
			} else {
				None
			}
		}
		node_txn[0].verify(|out|get_txout(out, &revoked_local_txn[0])).unwrap();
		node_txn[1].verify(|out|get_txout(out, &revoked_local_txn[0])).unwrap();
		node_txn[2].verify(|out|get_txout(out, &revoked_local_txn[0])).unwrap();

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[1].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[2].input[0].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		assert_eq!(node_txn[3].input.len(), 1);
		check_spends!(node_txn[3], chan_1.3.clone());

		assert_eq!(node_txn[4].input.len(), 1);
		let witness_script = node_txn[4].input[0].witness.last().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		assert_eq!(node_txn[4].input[0].previous_output.txid, node_txn[3].txid());
		assert_ne!(node_txn[4].input[0].previous_output.txid, node_txn[0].input[0].previous_output.txid);
		assert_ne!(node_txn[4].input[0].previous_output.txid, node_txn[1].input[0].previous_output.txid);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn test_htlc_on_chain_success() {
	// Test that in case of a unilateral close onchain, we detect the state of output thanks to
	// ChainWatchInterface and pass the preimage backward accordingly. So here we test that ChannelManager is
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

	let nodes = create_network(3, &[None, None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (our_payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let (our_payment_preimage_2, _payment_hash_2) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};

	// Broadcast legit commitment tx from C on B's chain
	// Broadcast HTLC Success transaction by C on received output from C's commitment tx on B's chain
	let commitment_tx = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(commitment_tx.len(), 1);
	check_spends!(commitment_tx[0], chan_2.3.clone());
	nodes[2].node.claim_funds(our_payment_preimage);
	nodes[2].node.claim_funds(our_payment_preimage_2);
	check_added_monitors!(nodes[2], 2);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);

	nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2]);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 1 (commitment tx), ChannelMonitor : 4 (2*2 * HTLC-Success tx)
	assert_eq!(node_txn.len(), 5);
	assert_eq!(node_txn[0], node_txn[3]);
	assert_eq!(node_txn[1], node_txn[4]);
	assert_eq!(node_txn[2], commitment_tx[0]);
	check_spends!(node_txn[0], commitment_tx[0].clone());
	check_spends!(node_txn[1], commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_eq!(node_txn[0].lock_time, 0);
	assert_eq!(node_txn[1].lock_time, 0);

	// Verify that B's ChannelManager is able to extract preimage from HTLC Success tx and pass it backward
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: node_txn}, 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	{
		let mut added_monitors = nodes[1].chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 2);
		assert_eq!(added_monitors[0].0.txid, chan_1.3.txid());
		assert_eq!(added_monitors[1].0.txid, chan_1.3.txid());
		added_monitors.clear();
	}
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	macro_rules! check_tx_local_broadcast {
		($node: expr, $htlc_offered: expr, $commitment_tx: expr, $chan_tx: expr) => { {
			// ChannelManager : 3 (commitment tx, 2*HTLC-Timeout tx), ChannelMonitor : 2 (timeout tx) * 2 (block-rescan)
			let mut node_txn = $node.tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 7);
			assert_eq!(node_txn[0], node_txn[5]);
			assert_eq!(node_txn[1], node_txn[6]);
			check_spends!(node_txn[0], $commitment_tx.clone());
			check_spends!(node_txn[1], $commitment_tx.clone());
			assert_ne!(node_txn[0].lock_time, 0);
			assert_ne!(node_txn[1].lock_time, 0);
			if $htlc_offered {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
				assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			} else {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
				assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
			}
			check_spends!(node_txn[2], $chan_tx.clone());
			check_spends!(node_txn[3], node_txn[2].clone());
			check_spends!(node_txn[4], node_txn[2].clone());
			assert_eq!(node_txn[2].input[0].witness.last().unwrap().len(), 71);
			assert_eq!(node_txn[3].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
			assert_eq!(node_txn[4].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
			assert!(node_txn[3].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			assert!(node_txn[4].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			assert_ne!(node_txn[3].lock_time, 0);
			assert_ne!(node_txn[4].lock_time, 0);
			node_txn.clear();
		} }
	}
	// nodes[1] now broadcasts its own local state as a fallback, suggesting an alternate
	// commitment transaction with a corresponding HTLC-Timeout transactions, as well as a
	// timeout-claim of the output that nodes[2] just claimed via success.
	check_tx_local_broadcast!(nodes[1], false, commitment_tx[0], chan_2.3);

	// Broadcast legit commitment tx from A on B's chain
	// Broadcast preimage tx by B on offered output from A commitment tx  on A's chain
	let commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	check_spends!(commitment_tx[0], chan_1.3.clone());
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[1]);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 1 (commitment tx), ChannelMonitor : 1 (HTLC-Success) * 2 (block-rescan)
	assert_eq!(node_txn.len(), 3);
	assert_eq!(node_txn[0], node_txn[2]);
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0].input.len(), 2);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[0].input[1].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[0].lock_time, 0);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
	check_spends!(node_txn[1], chan_1.3.clone());
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
	// We don't bother to check that B can claim the HTLC output on its commitment tx here as
	// we already checked the same situation with A.

	// Verify that A's ChannelManager is able to extract preimage from preimage tx and generate PaymentSent
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone(), node_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0]);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	let mut first_claimed = false;
	for event in events {
		match event {
			Event::PaymentSent { payment_preimage } => {
				if payment_preimage == our_payment_preimage {
					assert!(!first_claimed);
					first_claimed = true;
				} else {
					assert_eq!(payment_preimage, our_payment_preimage_2);
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	check_tx_local_broadcast!(nodes[0], true, commitment_tx[0], chan_1.3);
}

#[test]
fn test_htlc_on_chain_timeout() {
	// Test that in case of a unilateral close onchain, we detect the state of output thanks to
	// ChainWatchInterface and timeout the HTLC backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A ------------------> B ----------------------> C (timeout)
	//    B's commitment tx 		C's commitment tx
	//    	      \                                  \
	//    	   B's HTLC timeout tx		     B's timeout tx

	let nodes = create_network(3, &[None, None, None]);

	// Create some intial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network a bit by relaying one payment thorugh all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (_payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};

	// Broadcast legit commitment tx from C on B's chain
	let commitment_tx = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	check_spends!(commitment_tx[0], chan_2.3.clone());
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	check_added_monitors!(nodes[2], 0);
	expect_pending_htlcs_forwardable!(nodes[2]);
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
	nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2]);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 1 (commitment tx)
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan_2.3.clone());
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), 71);

	// Broadcast timeout transaction by B on received output from C's commitment tx on B's chain
	// Verify that B's ChannelManager is able to detect that HTLC is timeout by its own tx and react backward in consequence
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 200);
	let timeout_tx;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 8); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 6 (HTLC-Timeout tx, commitment tx, timeout tx) * 2 (block-rescan)
		assert_eq!(node_txn[0], node_txn[5]);
		assert_eq!(node_txn[1], node_txn[6]);
		assert_eq!(node_txn[2], node_txn[7]);
		check_spends!(node_txn[0], commitment_tx[0].clone());
		assert_eq!(node_txn[0].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[1], chan_2.3.clone());
		check_spends!(node_txn[2], node_txn[1].clone());
		assert_eq!(node_txn[1].clone().input[0].witness.last().unwrap().len(), 71);
		assert_eq!(node_txn[2].clone().input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[3], chan_2.3.clone());
		check_spends!(node_txn[4], node_txn[3].clone());
		assert_eq!(node_txn[3].input[0].witness.clone().last().unwrap().len(), 71);
		assert_eq!(node_txn[4].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		timeout_tx = node_txn[0].clone();
		node_txn.clear();
	}

	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![timeout_tx]}, 1);
	connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 1, true, header.bitcoin_hash());
	check_added_monitors!(nodes[1], 0);
	check_closed_broadcast!(nodes[1]);

	expect_pending_htlcs_forwardable!(nodes[1]);
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
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // Well... here we detect our own htlc_timeout_tx so no tx to be generated
	assert_eq!(node_txn.len(), 0);

	// Broadcast legit commitment tx from B on A's chain
	let commitment_tx = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	check_spends!(commitment_tx[0], chan_1.3.clone());

	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 200);
	check_closed_broadcast!(nodes[0]);
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 2 (timeout tx) * 2 block-rescan
	assert_eq!(node_txn.len(), 4);
	assert_eq!(node_txn[0], node_txn[3]);
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[1], chan_1.3.clone());
	check_spends!(node_txn[2], node_txn[1].clone());
	assert_eq!(node_txn[1].clone().input[0].witness.last().unwrap().len(), 71);
	assert_eq!(node_txn[2].clone().input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
}

#[test]
fn test_simple_commitment_revoked_fail_backward() {
	// Test that in case of a revoked commitment tx, we detect the resolution of output by justice tx
	// and fail backward accordingly.

	let nodes = create_network(3, &[None, None, None]);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 1, true, header.bitcoin_hash());
	check_added_monitors!(nodes[1], 0);
	check_closed_broadcast!(nodes[1]);

	expect_pending_htlcs_forwardable!(nodes[1]);
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

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]).unwrap();
			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
				_ => panic!("Unexpected event"),
			}
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}
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
	let mut nodes = create_network(3, &[None, None, None]);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], if no_to_remote { 10_000 } else { 3_000_000 });
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn[0].output.len(), if no_to_remote { 1 } else { 2 });
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let value = if use_dust {
		// The dust limit applied to HTLC outputs considers the fee of the HTLC transaction as
		// well, so HTLCs at exactly the dust limit will not be included in commitment txn.
		nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().our_dust_limit_satoshis * 1000
	} else { 3000000 };

	let (_, first_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, second_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, third_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);

	assert!(nodes[2].node.fail_htlc_backwards(&first_payment_hash));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	// Drop the last RAA from 3 -> 2

	assert!(nodes[2].node.fail_htlc_backwards(&second_payment_hash));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[2], 1);

	assert!(nodes[2].node.fail_htlc_backwards(&third_payment_hash));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
	// At this point first_payment_hash has dropped out of the latest two commitment
	// transactions that nodes[1] is tracking...
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is (still) in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[2], 1);

	// Add a fourth HTLC, this one will get sequestered away in nodes[1]'s holding cell waiting
	// on nodes[2]'s RAA.
	let route = nodes[1].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, fourth_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[1].node.send_payment(route, fourth_payment_hash).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 0);

	if deliver_bs_raa {
		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_raa).unwrap();
		// One monitor for the new revocation preimage, no second on as we won't generate a new
		// commitment transaction for nodes[0] until process_pending_htlc_forwards().
		check_added_monitors!(nodes[1], 1);
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		// Deliberately don't process the pending fail-back so they all fail back at once after
		// block connection just like the !deliver_bs_raa case
	}

	let mut failed_htlcs = HashSet::new();
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 1, true, header.bitcoin_hash());

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), if deliver_bs_raa { 1 } else { 2 });
	match events[0] {
		Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(*payment_hash, fourth_payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
	if !deliver_bs_raa {
		match events[1] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), if deliver_bs_raa { 3 } else { 2 });
	match events[if deliver_bs_raa { 1 } else { 0 }] {
		MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { .. } } => {},
		_ => panic!("Unexpected event"),
	}
	if deliver_bs_raa {
		match events[0] {
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
	match events[if deliver_bs_raa { 2 } else { 1 }] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 3);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]).unwrap();
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[1]).unwrap();
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[2]).unwrap();

			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_msg_events();
			// If we delivered B's RAA we got an unknown preimage error, not something
			// that we should update our routing table for.
			assert_eq!(events.len(), if deliver_bs_raa { 2 } else { 3 });
			for event in events {
				match event {
					MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
					_ => panic!("Unexpected event"),
				}
			}
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 3);
			match events[0] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[2] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
		},
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
fn test_htlc_ignore_latest_remote_commitment() {
	// Test that HTLC transactions spending the latest remote commitment transaction are simply
	// ignored if we cannot claim them. This originally tickled an invalid unwrap().
	let nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	route_payment(&nodes[0], &[&nodes[1]], 10000000);
	nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id);
	check_closed_broadcast!(nodes[0]);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 2);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&node_txn[0], &node_txn[1]], &[1; 2]);
	check_closed_broadcast!(nodes[1]);

	// Duplicate the block_connected call since this may happen due to other listeners
	// registering new transactions
	nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&node_txn[0], &node_txn[1]], &[1; 2]);
}

#[test]
fn test_force_close_fail_back() {
	// Check which HTLCs are failed-backwards on channel force-closure
	let mut nodes = create_network(3, &[None, None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, 42).unwrap();

	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let mut payment_event = {
		nodes[0].node.send_payment(route, our_payment_hash).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	check_added_monitors!(nodes[1], 1);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
	check_added_monitors!(nodes[2], 1);
	let (_, _) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	// nodes[2] now has the latest commitment transaction, but hasn't revoked its previous
	// state or updated nodes[1]' state. Now force-close and broadcast that commitment/HTLC
	// transaction and ensure nodes[1] doesn't fail-backwards (this was originally a bug!).

	nodes[2].node.force_close_channel(&payment_event.commitment_msg.channel_id);
	check_closed_broadcast!(nodes[2]);
	let tx = {
		let mut node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// Note that we don't bother broadcasting the HTLC-Success transaction here as we don't
		// have a use for it unless nodes[2] learns the preimage somehow, the funds will go
		// back to nodes[1] upon timeout otherwise.
		assert_eq!(node_txn.len(), 1);
		node_txn.remove(0)
	};

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&tx], &[1]);

	// Note no UpdateHTLCs event here from nodes[1] to nodes[0]!
	check_closed_broadcast!(nodes[1]);

	// Now check that if we add the preimage to ChannelMonitor it broadcasts our HTLC-Success..
	{
		let mut monitors = nodes[2].chan_monitor.simple_monitor.monitors.lock().unwrap();
		monitors.get_mut(&OutPoint::new(Sha256dHash::from_slice(&payment_event.commitment_msg.channel_id[..]).unwrap(), 0)).unwrap()
			.provide_payment_preimage(&our_payment_hash, &our_payment_preimage);
	}
	nodes[2].chain_monitor.block_connected_checked(&header, 1, &[&tx], &[1]);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	assert_eq!(node_txn[0].input.len(), 1);
	assert_eq!(node_txn[0].input[0].previous_output.txid, tx.txid());
	assert_eq!(node_txn[0].lock_time, 0); // Must be an HTLC-Success
	assert_eq!(node_txn[0].input[0].witness.len(), 5); // Must be an HTLC-Success

	check_spends!(node_txn[0], tx);
}

#[test]
fn test_unconf_chan() {
	// After creating a chan between nodes, we disconnect all blocks previously seen to force a channel close on nodes[0] side
	let nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let channel_state = nodes[0].node.channel_state.lock().unwrap();
	assert_eq!(channel_state.by_id.len(), 1);
	assert_eq!(channel_state.short_to_id.len(), 1);
	mem::drop(channel_state);

	let mut headers = Vec::new();
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	headers.push(header.clone());
	for _i in 2..100 {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		headers.push(header.clone());
	}
	let mut height = 99;
	while !headers.is_empty() {
		nodes[0].node.block_disconnected(&headers.pop().unwrap(), height);
		height -= 1;
	}
	check_closed_broadcast!(nodes[0]);
	let channel_state = nodes[0].node.channel_state.lock().unwrap();
	assert_eq!(channel_state.by_id.len(), 0);
	assert_eq!(channel_state.short_to_id.len(), 0);
}

#[test]
fn test_simple_peer_disconnect() {
	// Test that we can reconnect when there are no lost messages
	let nodes = create_network(3, &[None, None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_2 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_2);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_1);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	let payment_hash_6 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	claim_payment_along_route(&nodes[0], &vec!(&nodes[1], &nodes[2]), true, payment_preimage_3);
	fail_payment_along_route(&nodes[0], &[&nodes[1], &nodes[2]], true, payment_hash_5);

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (1, 0), (1, 0), (false, false));
	{
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage } => {
				assert_eq!(payment_preimage, payment_preimage_3);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentFailed { payment_hash, rejected_by_dest, .. } => {
				assert_eq!(payment_hash, payment_hash_5);
				assert!(rejected_by_dest);
			},
			_ => panic!("Unexpected event"),
		}
	}

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_4);
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_6);
}

fn do_test_drop_messages_peer_disconnect(messages_delivered: u8) {
	// Test that we can reconnect when in-flight HTLC updates get dropped
	let mut nodes = create_network(2, &[None, None]);
	if messages_delivered == 0 {
		create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001, LocalFeatures::new(), LocalFeatures::new());
		// nodes[1] doesn't receive the funding_locked message (it'll be re-sent on reconnect)
	} else {
		create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	}

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), Some(&nodes[0].node.list_usable_channels()), &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	let payment_event = {
		nodes[0].node.send_payment(route.clone(), payment_hash_1).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(nodes[1].node.get_our_node_id(), payment_event.node_id);

	if messages_delivered < 2 {
		// Drop the payment_event messages, and let them get re-generated in reconnect_nodes!
	} else {
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		if messages_delivered >= 3 {
			nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
			check_added_monitors!(nodes[1], 1);
			let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

			if messages_delivered >= 4 {
				nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[0], 1);

				if messages_delivered >= 5 {
					nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed).unwrap();
					let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[0], 1);

					if messages_delivered >= 6 {
						nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
						assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[1], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	if messages_delivered < 3 {
		// Even if the funding_locked messages get exchanged, as long as nothing further was
		// received on either side, both sides will need to resend them.
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 1), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 3 {
		// nodes[0] still wants its RAA + commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (true, false));
	} else if messages_delivered == 4 {
		// nodes[0] still wants its commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 5 {
		// nodes[1] still wants its final RAA
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, true));
	} else if messages_delivered == 6 {
		// Everything was delivered...
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	let events_1 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		Event::PendingHTLCsForwardable { .. } => { },
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[1].node.process_pending_htlc_forwards();

	let events_2 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors!(nodes[1], 1);

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
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlc).unwrap();

		let events_4 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!(payment_preimage_1, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}

		if messages_delivered >= 2 {
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
			check_added_monitors!(nodes[0], 1);
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

			if messages_delivered >= 3 {
				nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[1], 1);

				if messages_delivered >= 4 {
					nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed).unwrap();
					let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[1], 1);

					if messages_delivered >= 5 {
						nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
						assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[0], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	if messages_delivered < 2 {
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (1, 0), (0, 0), (0, 0), (false, false));
		//TODO: Deduplicate PaymentSent events, then enable this if:
		//if messages_delivered < 1 {
			let events_4 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_4.len(), 1);
			match events_4[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(payment_preimage_1, *payment_preimage);
				},
				_ => panic!("Unexpected event"),
			}
		//}
	} else if messages_delivered == 2 {
		// nodes[0] still wants its RAA + commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, true));
	} else if messages_delivered == 3 {
		// nodes[0] still wants its commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 4 {
		// nodes[1] still wants its final RAA
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (true, false));
	} else if messages_delivered == 5 {
		// Everything was delivered...
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	// Channel should still work fine...
	let payment_preimage_2 = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_drop_messages_peer_disconnect_a() {
	do_test_drop_messages_peer_disconnect(0);
	do_test_drop_messages_peer_disconnect(1);
	do_test_drop_messages_peer_disconnect(2);
	do_test_drop_messages_peer_disconnect(3);
}

#[test]
fn test_drop_messages_peer_disconnect_b() {
	do_test_drop_messages_peer_disconnect(4);
	do_test_drop_messages_peer_disconnect(5);
	do_test_drop_messages_peer_disconnect(6);
}

#[test]
fn test_funding_peer_disconnect() {
	// Test that we can lock in our funding tx while disconnected
	let nodes = create_network(2, &[None, None]);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, LocalFeatures::new(), LocalFeatures::new());

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	confirm_transaction(&nodes[0].chain_monitor, &tx, tx.version);
	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	reconnect_nodes(&nodes[0], &nodes[1], (false, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	confirm_transaction(&nodes[1].chain_monitor, &tx, tx.version);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 2);
	match events_2[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}
	match events_2[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	// TODO: We shouldn't need to manually pass list_usable_chanels here once we support
	// rebroadcasting announcement_signatures upon reconnect.

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), Some(&nodes[0].node.list_usable_channels()), &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage, _) = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
}

#[test]
fn test_drop_messages_peer_disconnect_dual_htlc() {
	// Test that we can handle reconnecting when both sides of a channel have pending
	// commitment_updates when we disconnect.
	let mut nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);

	nodes[0].node.send_payment(route.clone(), payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(nodes[1].node.claim_funds(payment_preimage_1));
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

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]).unwrap();
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed).unwrap();
			let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
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
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().update_add_htlcs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().commitment_signed).unwrap();
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), as_resp.1.as_ref().unwrap()).unwrap();
	let bs_second_commitment_signed = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_second_commitment_signed.update_add_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
	let as_commitment_signed = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_commitment_signed.update_add_htlcs.is_empty());
	assert!(as_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(as_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_signed.commitment_signed).unwrap();
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed.commitment_signed).unwrap();
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, amt: _ } => {
			assert_eq!(payment_hash_2, *payment_hash);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_invalid_channel_announcement() {
	//Test BOLT 7 channel_announcement msg requirement for final node, gather data to build customed channel_announcement msgs
	let secp_ctx = Secp256k1::new();
	let nodes = create_network(2, &[None, None]);

	let chan_announcement = create_chan_between_nodes(&nodes[0], &nodes[1], LocalFeatures::new(), LocalFeatures::new());

	let a_channel_lock = nodes[0].node.channel_state.lock().unwrap();
	let b_channel_lock = nodes[1].node.channel_state.lock().unwrap();
	let as_chan = a_channel_lock.by_id.get(&chan_announcement.3).unwrap();
	let bs_chan = b_channel_lock.by_id.get(&chan_announcement.3).unwrap();

	let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

	let as_bitcoin_key = PublicKey::from_secret_key(&secp_ctx, &as_chan.get_local_keys().funding_key);
	let bs_bitcoin_key = PublicKey::from_secret_key(&secp_ctx, &bs_chan.get_local_keys().funding_key);

	let as_network_key = nodes[0].node.get_our_node_id();
	let bs_network_key = nodes[1].node.get_our_node_id();

	let were_node_one = as_bitcoin_key.serialize()[..] < bs_bitcoin_key.serialize()[..];

	let mut chan_announcement;

	macro_rules! dummy_unsigned_msg {
		() => {
			msgs::UnsignedChannelAnnouncement {
				features: msgs::GlobalFeatures::new(),
				chain_hash: genesis_block(Network::Testnet).header.bitcoin_hash(),
				short_channel_id: as_chan.get_short_channel_id().unwrap(),
				node_id_1: if were_node_one { as_network_key } else { bs_network_key },
				node_id_2: if were_node_one { bs_network_key } else { as_network_key },
				bitcoin_key_1: if were_node_one { as_bitcoin_key } else { bs_bitcoin_key },
				bitcoin_key_2: if were_node_one { bs_bitcoin_key } else { as_bitcoin_key },
				excess_data: Vec::new(),
			};
		}
	}

	macro_rules! sign_msg {
		($unsigned_msg: expr) => {
			let msghash = Message::from_slice(&Sha256dHash::hash(&$unsigned_msg.encode()[..])[..]).unwrap();
			let as_bitcoin_sig = secp_ctx.sign(&msghash, &as_chan.get_local_keys().funding_key);
			let bs_bitcoin_sig = secp_ctx.sign(&msghash, &bs_chan.get_local_keys().funding_key);
			let as_node_sig = secp_ctx.sign(&msghash, &nodes[0].keys_manager.get_node_secret());
			let bs_node_sig = secp_ctx.sign(&msghash, &nodes[1].keys_manager.get_node_secret());
			chan_announcement = msgs::ChannelAnnouncement {
				node_signature_1 : if were_node_one { as_node_sig } else { bs_node_sig},
				node_signature_2 : if were_node_one { bs_node_sig } else { as_node_sig},
				bitcoin_signature_1: if were_node_one { as_bitcoin_sig } else { bs_bitcoin_sig },
				bitcoin_signature_2 : if were_node_one { bs_bitcoin_sig } else { as_bitcoin_sig },
				contents: $unsigned_msg
			}
		}
	}

	let unsigned_msg = dummy_unsigned_msg!();
	sign_msg!(unsigned_msg);
	assert_eq!(nodes[0].router.handle_channel_announcement(&chan_announcement).unwrap(), true);
	let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

	// Configured with Network::Testnet
	let mut unsigned_msg = dummy_unsigned_msg!();
	unsigned_msg.chain_hash = genesis_block(Network::Bitcoin).header.bitcoin_hash();
	sign_msg!(unsigned_msg);
	assert!(nodes[0].router.handle_channel_announcement(&chan_announcement).is_err());

	let mut unsigned_msg = dummy_unsigned_msg!();
	unsigned_msg.chain_hash = Sha256dHash::hash(&[1,2,3,4,5,6,7,8,9]);
	sign_msg!(unsigned_msg);
	assert!(nodes[0].router.handle_channel_announcement(&chan_announcement).is_err());
}

#[test]
fn test_no_txn_manager_serialize_deserialize() {
	let mut nodes = create_network(2, &[None, None]);

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, LocalFeatures::new(), LocalFeatures::new());

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new()), Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 })));
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let config = UserConfig::new();
	let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
	let (_, nodes_0_deserialized) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().unwrap(), &chan_0_monitor);
		<(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: config,
			keys_manager,
			fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
			monitor: nodes[0].chan_monitor.clone(),
			chain_monitor: nodes[0].chain_monitor.clone(),
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: Arc::new(test_utils::TestLogger::new()),
			channel_monitors: &channel_monitors,
		}).unwrap()
	};
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chan_monitor.add_update_monitor(chan_0_monitor.get_funding_txo().unwrap(), chan_0_monitor).is_ok());
	nodes[0].node = Arc::new(nodes_0_deserialized);
	let nodes_0_as_listener: Arc<ChainListener> = nodes[0].node.clone();
	nodes[0].chain_monitor.register_listener(Arc::downgrade(&nodes_0_as_listener));
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let (funding_locked, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);
	for node in nodes.iter() {
		assert!(node.router.handle_channel_announcement(&announcement).unwrap());
		node.router.handle_channel_update(&as_update).unwrap();
		node.router.handle_channel_update(&bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000000);
}

#[test]
fn test_simple_manager_serialize_deserialize() {
	let mut nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
	let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new()), Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 })));
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
	let (_, nodes_0_deserialized) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().unwrap(), &chan_0_monitor);
		<(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: UserConfig::new(),
			keys_manager,
			fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
			monitor: nodes[0].chan_monitor.clone(),
			chain_monitor: nodes[0].chain_monitor.clone(),
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: Arc::new(test_utils::TestLogger::new()),
			channel_monitors: &channel_monitors,
		}).unwrap()
	};
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chan_monitor.add_update_monitor(chan_0_monitor.get_funding_txo().unwrap(), chan_0_monitor).is_ok());
	nodes[0].node = Arc::new(nodes_0_deserialized);
	check_added_monitors!(nodes[0], 1);

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	fail_payment(&nodes[0], &[&nodes[1]], our_payment_hash);
	claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage);
}

#[test]
fn test_manager_serialize_deserialize_inconsistent_monitor() {
	// Test deserializing a ChannelManager with an out-of-date ChannelMonitor
	let mut nodes = create_network(4, &[None, None, None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 2, 0, LocalFeatures::new(), LocalFeatures::new());
	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 3, LocalFeatures::new(), LocalFeatures::new());

	let (our_payment_preimage, _) = route_payment(&nodes[2], &[&nodes[0], &nodes[1]], 1000000);

	// Serialize the ChannelManager here, but the monitor we keep up-to-date
	let nodes_0_serialized = nodes[0].node.encode();

	route_payment(&nodes[0], &[&nodes[3]], 1000000);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[3].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// Now the ChannelMonitor (which is now out-of-sync with ChannelManager for channel w/
	// nodes[3])
	let mut node_0_monitors_serialized = Vec::new();
	for monitor in nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter() {
		let mut writer = test_utils::TestVecWriter(Vec::new());
		monitor.1.write_for_disk(&mut writer).unwrap();
		node_0_monitors_serialized.push(writer.0);
	}

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new()), Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 })));
	let mut node_0_monitors = Vec::new();
	for serialized in node_0_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut read, Arc::new(test_utils::TestLogger::new())).unwrap();
		assert!(read.is_empty());
		node_0_monitors.push(monitor);
	}

	let mut nodes_0_read = &nodes_0_serialized[..];
	let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
	let (_, nodes_0_deserialized) = <(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
		default_config: UserConfig::new(),
		keys_manager,
		fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
		monitor: nodes[0].chan_monitor.clone(),
		chain_monitor: nodes[0].chain_monitor.clone(),
		tx_broadcaster: nodes[0].tx_broadcaster.clone(),
		logger: Arc::new(test_utils::TestLogger::new()),
		channel_monitors: &node_0_monitors.iter().map(|monitor| { (monitor.get_funding_txo().unwrap(), monitor) }).collect(),
	}).unwrap();
	assert!(nodes_0_read.is_empty());

	{ // Channel close should result in a commitment tx and an HTLC tx
		let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(txn.len(), 2);
		assert_eq!(txn[0].input[0].previous_output.txid, funding_tx.txid());
		assert_eq!(txn[1].input[0].previous_output.txid, txn[0].txid());
	}

	for monitor in node_0_monitors.drain(..) {
		assert!(nodes[0].chan_monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor).is_ok());
		check_added_monitors!(nodes[0], 1);
	}
	nodes[0].node = Arc::new(nodes_0_deserialized);

	// nodes[1] and nodes[2] have no lost state with nodes[0]...
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	reconnect_nodes(&nodes[0], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	//... and we can even still claim the payment!
	claim_payment(&nodes[2], &[&nodes[0], &nodes[1]], our_payment_preimage);

	nodes[3].node.peer_connected(&nodes[0].node.get_our_node_id());
	let reestablish = get_event_msg!(nodes[3], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[0].node.peer_connected(&nodes[3].node.get_our_node_id());
	if let Err(msgs::HandleError { action: Some(msgs::ErrorAction::SendErrorMessage { msg }), .. }) = nodes[0].node.handle_channel_reestablish(&nodes[3].node.get_our_node_id(), &reestablish) {
		assert_eq!(msg.channel_id, channel_id);
	} else { panic!("Unexpected result"); }
}

macro_rules! check_spendable_outputs {
	($node: expr, $der_idx: expr) => {
		{
			let events = $node.chan_monitor.simple_monitor.get_and_clear_pending_events();
			let mut txn = Vec::new();
			for event in events {
				match event {
					Event::SpendableOutputs { ref outputs } => {
						for outp in outputs {
							match *outp {
								SpendableOutputDescriptor::DynamicOutputP2WPKH { ref outpoint, ref key, ref output } => {
									let input = TxIn {
										previous_output: outpoint.clone(),
										script_sig: Script::new(),
										sequence: 0,
										witness: Vec::new(),
									};
									let outp = TxOut {
										script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
										value: output.value,
									};
									let mut spend_tx = Transaction {
										version: 2,
										lock_time: 0,
										input: vec![input],
										output: vec![outp],
									};
									let secp_ctx = Secp256k1::new();
									let remotepubkey = PublicKey::from_secret_key(&secp_ctx, &key);
									let witness_script = Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: remotepubkey}, Network::Testnet).script_pubkey();
									let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], &witness_script, output.value)[..]).unwrap();
									let remotesig = secp_ctx.sign(&sighash, key);
									spend_tx.input[0].witness.push(remotesig.serialize_der().to_vec());
									spend_tx.input[0].witness[0].push(SigHashType::All as u8);
									spend_tx.input[0].witness.push(remotepubkey.serialize().to_vec());
									txn.push(spend_tx);
								},
								SpendableOutputDescriptor::DynamicOutputP2WSH { ref outpoint, ref key, ref witness_script, ref to_self_delay, ref output } => {
									let input = TxIn {
										previous_output: outpoint.clone(),
										script_sig: Script::new(),
										sequence: *to_self_delay as u32,
										witness: Vec::new(),
									};
									let outp = TxOut {
										script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
										value: output.value,
									};
									let mut spend_tx = Transaction {
										version: 2,
										lock_time: 0,
										input: vec![input],
										output: vec![outp],
									};
									let secp_ctx = Secp256k1::new();
									let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], witness_script, output.value)[..]).unwrap();
									let local_delaysig = secp_ctx.sign(&sighash, key);
									spend_tx.input[0].witness.push(local_delaysig.serialize_der().to_vec());
									spend_tx.input[0].witness[0].push(SigHashType::All as u8);
									spend_tx.input[0].witness.push(vec!(0));
									spend_tx.input[0].witness.push(witness_script.clone().into_bytes());
									txn.push(spend_tx);
								},
								SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
									let secp_ctx = Secp256k1::new();
									let input = TxIn {
										previous_output: outpoint.clone(),
										script_sig: Script::new(),
										sequence: 0,
										witness: Vec::new(),
									};
									let outp = TxOut {
										script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
										value: output.value,
									};
									let mut spend_tx = Transaction {
										version: 2,
										lock_time: 0,
										input: vec![input],
										output: vec![outp.clone()],
									};
									let secret = {
										match ExtendedPrivKey::new_master(Network::Testnet, &$node.node_seed) {
											Ok(master_key) => {
												match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx($der_idx).expect("key space exhausted")) {
													Ok(key) => key,
													Err(_) => panic!("Your RNG is busted"),
												}
											}
											Err(_) => panic!("Your rng is busted"),
										}
									};
									let pubkey = ExtendedPubKey::from_private(&secp_ctx, &secret).public_key;
									let witness_script = Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
									let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], &witness_script, output.value)[..]).unwrap();
									let sig = secp_ctx.sign(&sighash, &secret.private_key.key);
									spend_tx.input[0].witness.push(sig.serialize_der().to_vec());
									spend_tx.input[0].witness[0].push(SigHashType::All as u8);
									spend_tx.input[0].witness.push(pubkey.key.serialize().to_vec());
									txn.push(spend_tx);
								},
							}
						}
					},
					_ => panic!("Unexpected event"),
				};
			}
			txn
		}
	}
}

#[test]
fn test_claim_sizeable_push_msat() {
	// Incidentally test SpendableOutput event generation due to detection of to_local output on commitment tx
	let nodes = create_network(2, &[None, None]);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000, LocalFeatures::new(), LocalFeatures::new());
	nodes[1].node.force_close_channel(&chan.2);
	check_closed_broadcast!(nodes[1]);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3.clone());
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 0);
	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0].clone());
}

#[test]
fn test_claim_on_remote_sizeable_push_msat() {
	// Same test as previous, just test on remote commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH

	let nodes = create_network(2, &[None, None]);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000, LocalFeatures::new(), LocalFeatures::new());
	nodes[0].node.force_close_channel(&chan.2);
	check_closed_broadcast!(nodes[0]);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3.clone());
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 0);
	check_closed_broadcast!(nodes[1]);
	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 2);
	assert_eq!(spend_txn[0], spend_txn[1]);
	check_spends!(spend_txn[0], node_txn[0].clone());
}

#[test]
fn test_claim_on_remote_revoked_sizeable_push_msat() {
	// Same test as previous, just test on remote revoked commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH

	let nodes = create_network(2, &[None, None]);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000, LocalFeatures::new(), LocalFeatures::new());
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);
	let  header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1]);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 4);
	assert_eq!(spend_txn[0], spend_txn[2]); // to_remote output on revoked remote commitment_tx
	check_spends!(spend_txn[0], revoked_local_txn[0].clone());
	assert_eq!(spend_txn[1], spend_txn[3]); // to_local output on local commitment tx
	check_spends!(spend_txn[1], node_txn[0].clone());
}

#[test]
fn test_static_spendable_outputs_preimage_tx() {
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;

	let commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.txid());

	// Settle A's commitment tx on B's chain
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	assert!(nodes[1].node.claim_funds(payment_preimage));
	check_added_monitors!(nodes[1], 1);
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()] }, 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}

	// Check B's monitor was able to send back output descriptor event for preimage tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap(); // ChannelManager : 1 (local commitment tx), ChannelMonitor: 2 (1 preimage tx) * 2 (block-rescan)
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0], node_txn[2]);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[1], chan_1.3.clone());

	let spend_txn = check_spendable_outputs!(nodes[1], 1); // , 0, 0, 1, 1);
	assert_eq!(spend_txn.len(), 2);
	assert_eq!(spend_txn[0], spend_txn[1]);
	check_spends!(spend_txn[0], node_txn[0].clone());
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_commitment_tx() {
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	let  header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1]);

	let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 3);
	assert_eq!(node_txn.pop().unwrap(), node_txn[0]);
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0].clone());

	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 2);
	assert_eq!(spend_txn[0], spend_txn[1]);
	check_spends!(spend_txn[0], node_txn[0].clone());
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_timeout_tx() {
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	// A will generate HTLC-Timeout from revoked commitment tx
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0]);

	let revoked_htlc_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(revoked_htlc_txn.len(), 3);
	assert_eq!(revoked_htlc_txn[0], revoked_htlc_txn[2]);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0].clone());
	check_spends!(revoked_htlc_txn[1], chan_1.3.clone());

	// B will generate justice tx from A's revoked commitment/HTLC tx
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1]);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 4);
	assert_eq!(node_txn[3].input.len(), 1);
	check_spends!(node_txn[3], revoked_htlc_txn[0].clone());

	// Check B's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 3);
	assert_eq!(spend_txn[0], spend_txn[1]);
	check_spends!(spend_txn[0], node_txn[0].clone());
	check_spends!(spend_txn[2], node_txn[3].clone());
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_success_tx() {
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	// B will generate HTLC-Success from revoked commitment tx
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1]);
	let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();

	assert_eq!(revoked_htlc_txn.len(), 3);
	assert_eq!(revoked_htlc_txn[0], revoked_htlc_txn[2]);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0].clone());

	// A will generate justice tx from B's revoked commitment/HTLC tx
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0]);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 4);
	assert_eq!(node_txn[3].input.len(), 1);
	check_spends!(node_txn[3], revoked_htlc_txn[0].clone());

	// Check A's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[0], 1);
	assert_eq!(spend_txn.len(), 5);
	assert_eq!(spend_txn[0], spend_txn[2]);
	assert_eq!(spend_txn[1], spend_txn[3]);
	check_spends!(spend_txn[0], revoked_local_txn[0].clone()); // spending to_remote output from revoked local tx
	check_spends!(spend_txn[1], node_txn[2].clone()); // spending justice tx output from revoked local tx htlc received output
	check_spends!(spend_txn[4], node_txn[3].clone()); // spending justice tx output on htlc success tx
}

#[test]
fn test_onchain_to_onchain_claim() {
	// Test that in case of channel closure, we detect the state of output thanks to
	// ChainWatchInterface and claim HTLC on downstream peer's remote commitment tx.
	// First, have C claim an HTLC against its own latest commitment transaction.
	// Then, broadcast these to B, which should update the monitor downstream on the A<->B
	// channel.
	// Finally, check that B will claim the HTLC output if A's latest commitment transaction
	// gets broadcast.

	let nodes = create_network(3, &[None, None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	let commitment_tx = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	check_spends!(commitment_tx[0], chan_2.3.clone());
	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());

	nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2]);

	let c_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 2 (commitment tx, HTLC-Success tx), ChannelMonitor : 1 (HTLC-Success tx)
	assert_eq!(c_txn.len(), 3);
	assert_eq!(c_txn[0], c_txn[2]);
	assert_eq!(commitment_tx[0], c_txn[1]);
	check_spends!(c_txn[1], chan_2.3.clone());
	check_spends!(c_txn[2], c_txn[1].clone());
	assert_eq!(c_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
	assert_eq!(c_txn[2].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(c_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_eq!(c_txn[0].lock_time, 0); // Success tx

	// So we broadcast C's commitment tx and HTLC-Success on B's chain, we should successfully be able to extract preimage and update downstream monitor
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![c_txn[1].clone(), c_txn[2].clone()]}, 1);
	{
		let mut b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(b_txn.len(), 4);
		assert_eq!(b_txn[0], b_txn[3]);
		check_spends!(b_txn[1], chan_2.3); // B local commitment tx, issued by ChannelManager
		check_spends!(b_txn[2], b_txn[1].clone()); // HTLC-Timeout on B local commitment tx, issued by ChannelManager
		assert_eq!(b_txn[2].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert!(b_txn[2].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
		assert_ne!(b_txn[2].lock_time, 0); // Timeout tx
		check_spends!(b_txn[0], c_txn[1].clone()); // timeout tx on C remote commitment tx, issued by ChannelMonitor, * 2 due to block rescan
		assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert!(b_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
		assert_ne!(b_txn[2].lock_time, 0); // Timeout tx
		b_txn.clear();
	}
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	check_added_monitors!(nodes[1], 1);
	match msg_events[0] {
		MessageSendEvent::BroadcastChannelUpdate {  .. } => {},
		_ => panic!("Unexpected event"),
	}
	match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	// Broadcast A's commitment tx on B's chain to see if we are able to claim inbound HTLC with our HTLC-Success tx
	let commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	let b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(b_txn.len(), 3);
	check_spends!(b_txn[1], chan_1.3); // Local commitment tx, issued by ChannelManager
	assert_eq!(b_txn[0], b_txn[2]); // HTLC-Success tx, issued by ChannelMonitor, * 2 due to block rescan
	check_spends!(b_txn[0], commitment_tx[0].clone());
	assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert!(b_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
	assert_eq!(b_txn[2].lock_time, 0); // Success tx

	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_duplicate_payment_hash_one_failure_one_success() {
	// Topology : A --> B --> C
	// We route 2 payments with same hash between B and C, one will be timeout, the other successfully claim
	let mut nodes = create_network(3, &[None, None, None]);

	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());

	let (our_payment_preimage, duplicate_payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 900000);
	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 900000).1, duplicate_payment_hash);

	let commitment_txn = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(commitment_txn[0].input.len(), 1);
	check_spends!(commitment_txn[0], chan_2.3.clone());

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1]);

	let htlc_timeout_tx;
	{ // Extract one of the two HTLC-Timeout transaction
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 7);
		assert_eq!(node_txn[0], node_txn[5]);
		assert_eq!(node_txn[1], node_txn[6]);
		check_spends!(node_txn[0], commitment_txn[0].clone());
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[1], commitment_txn[0].clone());
		assert_eq!(node_txn[1].input.len(), 1);
		assert_ne!(node_txn[0].input[0], node_txn[1].input[0]);
		check_spends!(node_txn[2], chan_2.3.clone());
		check_spends!(node_txn[3], node_txn[2].clone());
		check_spends!(node_txn[4], node_txn[2].clone());
		htlc_timeout_tx = node_txn[1].clone();
	}

	nodes[2].node.claim_funds(our_payment_preimage);
	nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[2], 2);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let htlc_success_txn: Vec<_> = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(htlc_success_txn.len(), 5);
	check_spends!(htlc_success_txn[2], chan_2.3.clone());
	assert_eq!(htlc_success_txn[0], htlc_success_txn[3]);
	assert_eq!(htlc_success_txn[0].input.len(), 1);
	assert_eq!(htlc_success_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(htlc_success_txn[1], htlc_success_txn[4]);
	assert_eq!(htlc_success_txn[1].input.len(), 1);
	assert_eq!(htlc_success_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_ne!(htlc_success_txn[0].input[0], htlc_success_txn[1].input[0]);
	check_spends!(htlc_success_txn[0], commitment_txn[0].clone());
	check_spends!(htlc_success_txn[1], commitment_txn[0].clone());

	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![htlc_timeout_tx] }, 200);
	connect_blocks(&nodes[1].chain_monitor, ANTI_REORG_DELAY - 1, 200, true, header.bitcoin_hash());
	expect_pending_htlcs_forwardable!(nodes[1]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert_eq!(htlc_updates.update_fail_htlcs[0].htlc_id, 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	{
		commitment_signed_dance!(nodes[0], nodes[1], &htlc_updates.commitment_signed, false, true);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelClosed { .. }  } => {
			},
			_ => { panic!("Unexpected event"); }
		}
	}
	let events = nodes[0].node.get_and_clear_pending_events();
	match events[0] {
		Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(*payment_hash, duplicate_payment_hash);
		}
		_ => panic!("Unexpected event"),
	}

	// Solve 2nd HTLC by broadcasting on B's chain HTLC-Success Tx from C
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![htlc_success_txn[0].clone()] }, 200);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert_eq!(updates.update_fulfill_htlcs[0].htlc_id, 0);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], &updates.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, our_payment_preimage);
		}
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_dynamic_spendable_outputs_local_htlc_success_tx() {
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000).0;
	let local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3.clone());

	// Give B knowledge of preimage to be able to generate a local HTLC-Success Tx
	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![local_txn[0].clone()] }, 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn[0].input.len(), 1);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[0], local_txn[0].clone());

	// Verify that B is able to spend its own HTLC-Success tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[1], 1);
	assert_eq!(spend_txn.len(), 2);
	check_spends!(spend_txn[0], node_txn[0].clone());
	check_spends!(spend_txn[1], node_txn[2].clone());
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
	let nodes = create_network(6, &[None, None, None, None, None, None]);

	create_announced_chan_between_nodes(&nodes, 0, 2, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new());
	let chan = create_announced_chan_between_nodes(&nodes, 2, 3, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 3, 4, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes(&nodes, 3, 5, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance and check output sanity...
	send_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 500000);
	send_payment(&nodes[1], &[&nodes[2], &nodes[3], &nodes[5]], 500000);
	assert_eq!(nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn[0].output.len(), 2);

	let ds_dust_limit = nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().our_dust_limit_satoshis;
	// 0th HTLC:
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 1st HTLC:
	let (_, payment_hash_2) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	let route = nodes[1].router.get_route(&nodes[5].node.get_our_node_id(), None, &Vec::new(), ds_dust_limit*1000, TEST_FINAL_CLTV).unwrap();
	// 2nd HTLC:
	send_along_route_with_hash(&nodes[1], route.clone(), &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_1); // not added < dust limit + HTLC tx fee
	// 3rd HTLC:
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_2); // not added < dust limit + HTLC tx fee
	// 4th HTLC:
	let (_, payment_hash_3) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 5th HTLC:
	let (_, payment_hash_4) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	let route = nodes[1].router.get_route(&nodes[5].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	// 6th HTLC:
	send_along_route_with_hash(&nodes[1], route.clone(), &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_3);
	// 7th HTLC:
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_4);

	// 8th HTLC:
	let (_, payment_hash_5) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 9th HTLC:
	let route = nodes[1].router.get_route(&nodes[5].node.get_our_node_id(), None, &Vec::new(), ds_dust_limit*1000, TEST_FINAL_CLTV).unwrap();
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_5); // not added < dust limit + HTLC tx fee

	// 10th HTLC:
	let (_, payment_hash_6) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 11th HTLC:
	let route = nodes[1].router.get_route(&nodes[5].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_6);

	// Double-check that six of the new HTLC were added
	// We now have six HTLCs pending over the dust limit and six HTLCs under the dust limit (ie,
	// with to_local and to_remote outputs, 8 outputs and 6 HTLCs not included).
	assert_eq!(nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.len(), 1);
	assert_eq!(nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn[0].output.len(), 8);

	// Now fail back three of the over-dust-limit and three of the under-dust-limit payments in one go.
	// Fail 0th below-dust, 4th above-dust, 8th above-dust, 10th below-dust HTLCs
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_1));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_3));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_5));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_6));
	check_added_monitors!(nodes[4], 0);
	expect_pending_htlcs_forwardable!(nodes[4]);
	check_added_monitors!(nodes[4], 1);

	let four_removes = get_htlc_update_msgs!(nodes[4], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[0]).unwrap();
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[1]).unwrap();
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[2]).unwrap();
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[3]).unwrap();
	commitment_signed_dance!(nodes[3], nodes[4], four_removes.commitment_signed, false);

	// Fail 3rd below-dust and 7th above-dust HTLCs
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_2));
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_4));
	check_added_monitors!(nodes[5], 0);
	expect_pending_htlcs_forwardable!(nodes[5]);
	check_added_monitors!(nodes[5], 1);

	let two_removes = get_htlc_update_msgs!(nodes[5], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[0]).unwrap();
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[1]).unwrap();
	commitment_signed_dance!(nodes[3], nodes[5], two_removes.commitment_signed, false);

	let ds_prev_commitment_tx = nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();

	expect_pending_htlcs_forwardable!(nodes[3]);
	check_added_monitors!(nodes[3], 1);
	let six_removes = get_htlc_update_msgs!(nodes[3], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[0]).unwrap();
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[1]).unwrap();
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[2]).unwrap();
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[3]).unwrap();
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[4]).unwrap();
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[5]).unwrap();
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
	let ds_last_commitment_tx = nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	if announce_latest {
		nodes[2].chain_monitor.block_connected_checked(&header, 1, &[&ds_last_commitment_tx[0]], &[1; 1]);
	} else {
		nodes[2].chain_monitor.block_connected_checked(&header, 1, &[&ds_prev_commitment_tx[0]], &[1; 1]);
	}
	connect_blocks(&nodes[2].chain_monitor, ANTI_REORG_DELAY - 1, 1, true,  header.bitcoin_hash());
	check_closed_broadcast!(nodes[2]);
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 2);

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
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[1]).unwrap();
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[2]).unwrap();
				if announce_latest {
					target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[3]).unwrap();
					if *node_id == nodes[0].node.get_our_node_id() {
						target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[4]).unwrap();
					}
				}
				commitment_signed_dance!(target, nodes[2], updates.commitment_signed, false, true);
			},
			_ => panic!("Unexpected event"),
		}
	}

	let as_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(as_events.len(), if announce_latest { 5 } else { 3 });
	let mut as_failds = HashSet::new();
	for event in as_events.iter() {
		if let &Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, .. } = event {
			assert!(as_failds.insert(*payment_hash));
			if *payment_hash != payment_hash_2 {
				assert_eq!(*rejected_by_dest, deliver_last_raa);
			} else {
				assert!(!rejected_by_dest);
			}
		} else { panic!("Unexpected event"); }
	}
	assert!(as_failds.contains(&payment_hash_1));
	assert!(as_failds.contains(&payment_hash_2));
	if announce_latest {
		assert!(as_failds.contains(&payment_hash_3));
		assert!(as_failds.contains(&payment_hash_5));
	}
	assert!(as_failds.contains(&payment_hash_6));

	let bs_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(bs_events.len(), if announce_latest { 4 } else { 3 });
	let mut bs_failds = HashSet::new();
	for event in bs_events.iter() {
		if let &Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, .. } = event {
			assert!(bs_failds.insert(*payment_hash));
			if *payment_hash != payment_hash_1 && *payment_hash != payment_hash_5 {
				assert_eq!(*rejected_by_dest, deliver_last_raa);
			} else {
				assert!(!rejected_by_dest);
			}
		} else { panic!("Unexpected event"); }
	}
	assert!(bs_failds.contains(&payment_hash_1));
	assert!(bs_failds.contains(&payment_hash_2));
	if announce_latest {
		assert!(bs_failds.contains(&payment_hash_4));
	}
	assert!(bs_failds.contains(&payment_hash_5));

	// For each HTLC which was not failed-back by normal process (ie deliver_last_raa), we should
	// get a PaymentFailureNetworkUpdate. A should have gotten 4 HTLCs which were failed-back due
	// to unknown-preimage-etc, B should have gotten 2. Thus, in the
	// announce_latest && deliver_last_raa case, we should have 5-4=1 and 4-2=2
	// PaymentFailureNetworkUpdates.
	let as_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_msg_events.len(), if deliver_last_raa { 1 } else if !announce_latest { 3 } else { 5 });
	let bs_msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msg_events.len(), if deliver_last_raa { 2 } else if !announce_latest { 3 } else { 4 });
	for event in as_msg_events.iter().chain(bs_msg_events.iter()) {
		match event {
			&MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
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
	let nodes = create_network(2, &[None, None]);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000).0;
	let local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3.clone());

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![local_txn[0].clone()] }, 200);
	check_closed_broadcast!(nodes[0]);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn[0].input.len(), 1);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[0], local_txn[0].clone());

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[0], 1);
	assert_eq!(spend_txn.len(), 8);
	assert_eq!(spend_txn[0], spend_txn[2]);
	assert_eq!(spend_txn[0], spend_txn[4]);
	assert_eq!(spend_txn[0], spend_txn[6]);
	assert_eq!(spend_txn[1], spend_txn[3]);
	assert_eq!(spend_txn[1], spend_txn[5]);
	assert_eq!(spend_txn[1], spend_txn[7]);
	check_spends!(spend_txn[0], local_txn[0].clone());
	check_spends!(spend_txn[1], node_txn[0].clone());
}

#[test]
fn test_static_output_closing_tx() {
	let nodes = create_network(2, &[None, None]);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![closing_tx.clone()] }, 1);
	let spend_txn = check_spendable_outputs!(nodes[0], 2);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx.clone());

	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![closing_tx.clone()] }, 1);
	let spend_txn = check_spendable_outputs!(nodes[1], 2);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);
}

fn do_htlc_claim_local_commitment_only(use_dust: bool) {
	let nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], if use_dust { 50000 } else { 3000000 });

	// Claim the payment, but don't deliver A's commitment_signed, resulting in the HTLC only being
	// present in B's local commitment transaction, but none of A's commitment transactions.
	assert!(nodes[1].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fulfill_htlcs[0]).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { payment_preimage } => {
			assert_eq!(payment_preimage, our_payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0).unwrap();
	check_added_monitors!(nodes[1], 1);

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	for i in 1..TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + CHAN_CONFIRM_DEPTH + 1 {
		nodes[1].chain_monitor.block_connected_checked(&header, i, &Vec::new(), &Vec::new());
		header.prev_blockhash = header.bitcoin_hash();
	}
	test_txn_broadcast(&nodes[1], &chan, None, if use_dust { HTLCType::NONE } else { HTLCType::SUCCESS });
	check_closed_broadcast!(nodes[1]);
}

fn do_htlc_claim_current_remote_commitment_only(use_dust: bool) {
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), if use_dust { 50000 } else { 3000000 }, TEST_FINAL_CLTV).unwrap();
	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);

	let _as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// As far as A is concerned, the HTLC is now present only in the latest remote commitment
	// transaction, however it is not in A's latest local commitment, so we can just broadcast that
	// to "time out" the HTLC.

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	for i in 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + CHAN_CONFIRM_DEPTH + 1 {
		nodes[0].chain_monitor.block_connected_checked(&header, i, &Vec::new(), &Vec::new());
		header.prev_blockhash = header.bitcoin_hash();
	}
	test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
	check_closed_broadcast!(nodes[0]);
}

fn do_htlc_claim_previous_remote_commitment_only(use_dust: bool, check_revoke_no_close: bool) {
	let nodes = create_network(3, &[None, None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// Fail the payment, but don't deliver A's final RAA, resulting in the HTLC only being present
	// in B's previous (unrevoked) commitment transaction, but none of A's commitment transactions.
	// Also optionally test that we *don't* fail the channel in case the commitment transaction was
	// actually revoked.
	let htlc_value = if use_dust { 50000 } else { 3000000 };
	let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], htlc_value);
	assert!(nodes[1].node.fail_htlc_backwards(&our_payment_hash));
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0).unwrap();
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_updates.1).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	if check_revoke_no_close {
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	for i in 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + CHAN_CONFIRM_DEPTH + 1 {
		nodes[0].chain_monitor.block_connected_checked(&header, i, &Vec::new(), &Vec::new());
		header.prev_blockhash = header.bitcoin_hash();
	}
	if !check_revoke_no_close {
		test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
		check_closed_broadcast!(nodes[0]);
	} else {
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, rejected_by_dest, .. } => {
				assert_eq!(payment_hash, our_payment_hash);
				assert!(rejected_by_dest);
			},
			_ => panic!("Unexpected event"),
		}
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

fn run_onion_failure_test<F1,F2>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, callback_msg: F1, callback_node: F2, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: FnMut(),
{
	run_onion_failure_test_with_fail_intercept(_name, test_case, nodes, route, payment_hash, callback_msg, |_|{}, callback_node, expected_retryable, expected_error_code, expected_channel_update);
}

// test_case
// 0: node1 fails backward
// 1: final node fails backward
// 2: payment completed but the user rejects the payment
// 3: final node fails backward (but tamper onion payloads from node0)
// 100: trigger error in the intermediate node and tamper returning fail_htlc
// 200: trigger error in the final node and tamper returning fail_htlc
fn run_onion_failure_test_with_fail_intercept<F1,F2,F3>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, mut callback_msg: F1, mut callback_fail: F2, mut callback_node: F3, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: for <'a> FnMut(&'a mut msgs::UpdateFailHTLC),
				F3: FnMut(),
{

	// reset block height
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	for ix in 0..nodes.len() {
		nodes[ix].chain_monitor.block_connected_checked(&header, 1, &Vec::new()[..], &[0; 0]);
	}

	macro_rules! expect_event {
		($node: expr, $event_type: path) => {{
			let events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$event_type { .. } => {},
				_ => panic!("Unexpected event"),
			}
		}}
	}

	macro_rules! expect_htlc_forward {
		($node: expr) => {{
			expect_event!($node, Event::PendingHTLCsForwardable);
			$node.node.process_pending_htlc_forwards();
		}}
	}

	// 0 ~~> 2 send payment
	nodes[0].node.send_payment(route.clone(), payment_hash.clone()).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	// temper update_add (0 => 1)
	let mut update_add_0 = update_0.update_add_htlcs[0].clone();
	if test_case == 0 || test_case == 3 || test_case == 100 {
		callback_msg(&mut update_add_0);
		callback_node();
	}
	// 0 => 1 update_add & CS
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add_0).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1_0 = match test_case {
		0|100 => { // intermediate node failure; fail backward to 0
			let update_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			assert!(update_1_0.update_fail_htlcs.len()+update_1_0.update_fail_malformed_htlcs.len()==1 && (update_1_0.update_fail_htlcs.len()==1 || update_1_0.update_fail_malformed_htlcs.len()==1));
			update_1_0
		},
		1|2|3|200 => { // final node failure; forwarding to 2
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			// forwarding on 1
			if test_case != 200 {
				callback_node();
			}
			expect_htlc_forward!(&nodes[1]);

			let update_1 = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
			check_added_monitors!(&nodes[1], 1);
			assert_eq!(update_1.update_add_htlcs.len(), 1);
			// tamper update_add (1 => 2)
			let mut update_add_1 = update_1.update_add_htlcs[0].clone();
			if test_case != 3 && test_case != 200 {
				callback_msg(&mut update_add_1);
			}

			// 1 => 2
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add_1).unwrap();
			commitment_signed_dance!(nodes[2], nodes[1], update_1.commitment_signed, false, true);

			if test_case == 2 || test_case == 200 {
				expect_htlc_forward!(&nodes[2]);
				expect_event!(&nodes[2], Event::PaymentReceived);
				callback_node();
				expect_pending_htlcs_forwardable!(nodes[2]);
			}

			let update_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
			if test_case == 2 || test_case == 200 {
				check_added_monitors!(&nodes[2], 1);
			}
			assert!(update_2_1.update_fail_htlcs.len() == 1);

			let mut fail_msg = update_2_1.update_fail_htlcs[0].clone();
			if test_case == 200 {
				callback_fail(&mut fail_msg);
			}

			// 2 => 1
			nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &fail_msg).unwrap();
			commitment_signed_dance!(nodes[1], nodes[2], update_2_1.commitment_signed, true);

			// backward fail on 1
			let update_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			assert!(update_1_0.update_fail_htlcs.len() == 1);
			update_1_0
		},
		_ => unreachable!(),
	};

	// 1 => 0 commitment_signed_dance
	if update_1_0.update_fail_htlcs.len() > 0 {
		let mut fail_msg = update_1_0.update_fail_htlcs[0].clone();
		if test_case == 100 {
			callback_fail(&mut fail_msg);
		}
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg).unwrap();
	} else {
		nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_1_0.update_fail_malformed_htlcs[0]).unwrap();
	};

	commitment_signed_dance!(nodes[0], nodes[1], update_1_0.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	if let &Event::PaymentFailed { payment_hash:_, ref rejected_by_dest, ref error_code } = &events[0] {
		assert_eq!(*rejected_by_dest, !expected_retryable);
		assert_eq!(*error_code, expected_error_code);
	} else {
		panic!("Uexpected event");
	}

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	if expected_channel_update.is_some() {
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::PaymentFailureNetworkUpdate { ref update } => {
				match update {
					&HTLCFailChannelUpdate::ChannelUpdateMessage { .. } => {
						if let HTLCFailChannelUpdate::ChannelUpdateMessage { .. } = expected_channel_update.unwrap() {} else {
							panic!("channel_update not found!");
						}
					},
					&HTLCFailChannelUpdate::ChannelClosed { ref short_channel_id, ref is_permanent } => {
						if let HTLCFailChannelUpdate::ChannelClosed { short_channel_id: ref expected_short_channel_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*short_channel_id == *expected_short_channel_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
					&HTLCFailChannelUpdate::NodeFailure { ref node_id, ref is_permanent } => {
						if let HTLCFailChannelUpdate::NodeFailure { node_id: ref expected_node_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*node_id == *expected_node_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
				}
			},
			_ => panic!("Unexpected message event"),
		}
	} else {
		assert_eq!(events.len(), 0);
	}
}

impl msgs::ChannelUpdate {
	fn dummy() -> msgs::ChannelUpdate {
		use secp256k1::ffi::Signature as FFISignature;
		use secp256k1::Signature;
		msgs::ChannelUpdate {
			signature: Signature::from(FFISignature::new()),
			contents: msgs::UnsignedChannelUpdate {
				chain_hash: Sha256dHash::hash(&vec![0u8][..]),
				short_channel_id: 0,
				timestamp: 0,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: vec![],
			}
		}
	}
}

#[test]
fn test_onion_failure() {
	use ln::msgs::ChannelUpdate;
	use ln::channelmanager::CLTV_FAR_FAR_AWAY;
	use secp256k1;

	const BADONION: u16 = 0x8000;
	const PERM: u16 = 0x4000;
	const NODE: u16 = 0x2000;
	const UPDATE: u16 = 0x1000;

	let mut nodes = create_network(3, &[None, None, None]);
	for node in nodes.iter() {
		*node.keys_manager.override_session_priv.lock().unwrap() = Some(SecretKey::from_slice(&[3; 32]).unwrap());
	}
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new()), create_announced_chan_between_nodes(&nodes, 1, 2, LocalFeatures::new(), LocalFeatures::new())];
	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap();
	// positve case
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 40000);

	// intermediate node failure
	run_onion_failure_test("invalid_realm", 0, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height).unwrap();
		onion_payloads[0].realm = 3;
		msg.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);
	}, ||{}, true, Some(PERM|1), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));//XXX incremented channels idx here

	// final node failure
	run_onion_failure_test("invalid_realm", 3, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height).unwrap();
		onion_payloads[1].realm = 3;
		msg.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);
	}, ||{}, false, Some(PERM|1), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	// the following three with run_onion_failure_test_with_fail_intercept() test only the origin node
	// receiving simulated fail messages
	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 100, &nodes, &route, &payment_hash, |msg| {
		// trigger error
		msg.amount_msat -= 1;
	}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], NODE|2, &[0;0]);
	}, ||{}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: false}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[1].pubkey, is_permanent: false}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{}, true, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[1].pubkey, is_permanent: true}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, true, Some(PERM|NODE|3), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|NODE|3), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[1].pubkey, is_permanent: true}));

	run_onion_failure_test("invalid_onion_version", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.version = 1; }, ||{}, true,
		Some(BADONION|PERM|4), None);

	run_onion_failure_test("invalid_onion_hmac", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.hmac = [3; 32]; }, ||{}, true,
		Some(BADONION|PERM|5), None);

	run_onion_failure_test("invalid_onion_key", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.public_key = Err(secp256k1::Error::InvalidPublicKey);}, ||{}, true,
		Some(BADONION|PERM|6), None);

	run_onion_failure_test_with_fail_intercept("temporary_channel_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], UPDATE|7, &ChannelUpdate::dummy().encode_with_len()[..]);
	}, ||{}, true, Some(UPDATE|7), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test_with_fail_intercept("permanent_channel_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|8, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|8), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test_with_fail_intercept("required_channel_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|9, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|9), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	let mut bogus_route = route.clone();
	bogus_route.hops[1].short_channel_id -= 1;
	run_onion_failure_test("unknown_next_peer", 0, &nodes, &bogus_route, &payment_hash, |_| {}, ||{}, true, Some(PERM|10),
	  Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: bogus_route.hops[1].short_channel_id, is_permanent:true}));

	let amt_to_forward = nodes[1].node.channel_state.lock().unwrap().by_id.get(&channels[1].2).unwrap().get_their_htlc_minimum_msat() - 1;
	let mut bogus_route = route.clone();
	let route_len = bogus_route.hops.len();
	bogus_route.hops[route_len-1].fee_msat = amt_to_forward;
	run_onion_failure_test("amount_below_minimum", 0, &nodes, &bogus_route, &payment_hash, |_| {}, ||{}, true, Some(UPDATE|11), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	//TODO: with new config API, we will be able to generate both valid and
	//invalid channel_update cases.
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id: channels[0].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test("incorrect_cltv_expiry", 0, &nodes, &route, &payment_hash, |msg| {
		// need to violate: cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
		msg.cltv_expiry -= 1;
	}, || {}, true, Some(UPDATE|13), Some(msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id: channels[0].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test("expiry_too_soon", 0, &nodes, &route, &payment_hash, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_checked(&header, height, &Vec::new()[..], &[0; 0]);
	}, ||{}, true, Some(UPDATE|14), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test("unknown_payment_hash", 2, &nodes, &route, &payment_hash, |_| {}, || {
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|15), None);

	run_onion_failure_test("final_expiry_too_soon", 1, &nodes, &route, &payment_hash, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[2].chain_monitor.block_connected_checked(&header, height, &Vec::new()[..], &[0; 0]);
	}, || {}, true, Some(17), None);

	run_onion_failure_test("final_incorrect_cltv_expiry", 1, &nodes, &route, &payment_hash, |_| {}, || {
		for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().borrow_parts().forward_htlcs.iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC { ref mut forward_info, .. } =>
						forward_info.outgoing_cltv_value += 1,
					_ => {},
				}
			}
		}
	}, true, Some(18), None);

	run_onion_failure_test("final_incorrect_htlc_amount", 1, &nodes, &route, &payment_hash, |_| {}, || {
		// violate amt_to_forward > msg.amount_msat
		for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().borrow_parts().forward_htlcs.iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC { ref mut forward_info, .. } =>
						forward_info.amt_to_forward -= 1,
					_ => {},
				}
			}
		}
	}, true, Some(19), None);

	run_onion_failure_test("channel_disabled", 0, &nodes, &route, &payment_hash, |_| {}, || {
		// disconnect event to the channel between nodes[1] ~ nodes[2]
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
		nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	}, true, Some(UPDATE|20), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));
	reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	run_onion_failure_test("expiry_too_far", 0, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let mut route = route.clone();
		let height = 1;
		route.hops[1].cltv_expiry_delta += CLTV_FAR_FAR_AWAY + route.hops[0].cltv_expiry_delta + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		let (onion_payloads, _, htlc_cltv) = onion_utils::build_onion_payloads(&route, height).unwrap();
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);
		msg.cltv_expiry = htlc_cltv;
		msg.onion_routing_packet = onion_packet;
	}, ||{}, true, Some(21), None);
}

#[test]
#[should_panic]
fn bolt2_open_channel_sending_node_checks_part1() { //This test needs to be on its own as we are catching a panic
	let nodes = create_network(2, &[None, None]);
	//Force duplicate channel ids
	for node in nodes.iter() {
		*node.keys_manager.override_channel_id_priv.lock().unwrap() = Some([0; 32]);
	}

	// BOLT #2 spec: Sending node must ensure temporary_channel_id is unique from any other channel ID with the same peer.
	let channel_value_satoshis=10000;
	let push_msat=10001;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42).unwrap();
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), LocalFeatures::new(), &node0_to_1_send_open_channel).unwrap();

	//Create a second channel with a channel_id collision
	assert!(nodes[0].node.create_channel(nodes[0].node.get_our_node_id(), channel_value_satoshis, push_msat, 42).is_err());
}

#[test]
fn bolt2_open_channel_sending_node_checks_part2() {
	let nodes = create_network(2, &[None, None]);

	// BOLT #2 spec: Sending node must set funding_satoshis to less than 2^24 satoshis
	let channel_value_satoshis=2^24;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42).is_err());

	// BOLT #2 spec: Sending node must set push_msat to equal or less than 1000 * funding_satoshis
	let channel_value_satoshis=10000;
	// Test when push_msat is equal to 1000 * funding_satoshis.
	let push_msat=1000*channel_value_satoshis+1;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42).is_err());

	// BOLT #2 spec: Sending node must set set channel_reserve_satoshis greater than or equal to dust_limit_satoshis
	let channel_value_satoshis=10000;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42).is_ok()); //Create a valid channel
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(node0_to_1_send_open_channel.channel_reserve_satoshis>=node0_to_1_send_open_channel.dust_limit_satoshis);

	// BOLT #2 spec: Sending node must set undefined bits in channel_flags to 0
	// Only the least-significant bit of channel_flags is currently defined resulting in channel_flags only having one of two possible states 0 or 1
	assert!(node0_to_1_send_open_channel.channel_flags<=1);

	// BOLT #2 spec: Sending node should set to_self_delay sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehaviour by the receiver.
	assert!(BREAKDOWN_TIMEOUT>0);
	assert!(node0_to_1_send_open_channel.to_self_delay==BREAKDOWN_TIMEOUT);

	// BOLT #2 spec: Sending node must ensure the chain_hash value identifies the chain it wishes to open the channel within.
	let chain_hash=genesis_block(Network::Testnet).header.bitcoin_hash();
	assert_eq!(node0_to_1_send_open_channel.chain_hash,chain_hash);

	// BOLT #2 spec: Sending node must set funding_pubkey, revocation_basepoint, htlc_basepoint, payment_basepoint, and delayed_payment_basepoint to valid DER-encoded, compressed, secp256k1 pubkeys.
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.funding_pubkey.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.revocation_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.htlc_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.payment_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.delayed_payment_basepoint.serialize()).is_ok());
}

// BOLT 2 Requirements for the Sender when constructing and sending an update_add_htlc message.
// BOLT 2 Requirement: MUST NOT offer amount_msat it cannot pay for in the remote commitment transaction at the current feerate_per_kw (see "Updating Fees") while maintaining its channel reserve.
//TODO: I don't believe this is explicitly enforced when sending an HTLC but as the Fee aspect of the BOLT specs is in flux leaving this as a TODO.

#[test]
fn test_update_add_htlc_bolt2_sender_value_below_minimum_msat() {
	//BOLT2 Requirement: MUST offer amount_msat greater than 0.
	//BOLT2 Requirement: MUST NOT offer amount_msat below the receiving node's htlc_minimum_msat (same validation check catches both of these)
	let mut nodes = create_network(2, &[None, None]);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, LocalFeatures::new(), LocalFeatures::new());
	let mut route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	route.hops[0].fee_msat = 0;

	let err = nodes[0].node.send_payment(route, our_payment_hash);

	if let Err(APIError::ChannelUnavailable{err}) = err {
		assert_eq!(err, "Cannot send less than their minimum HTLC value");
	} else {
		assert!(false);
	}
}

#[test]
fn test_update_add_htlc_bolt2_sender_cltv_expiry_too_high() {
	//BOLT 2 Requirement: MUST set cltv_expiry less than 500000000.
	//It is enforced when constructing a route.
	let mut nodes = create_network(2, &[None, None]);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 0, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000000, 500000001).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let err = nodes[0].node.send_payment(route, our_payment_hash);

	if let Err(APIError::RouteError{err}) = err {
		assert_eq!(err, "Channel CLTV overflowed?!");
	} else {
		assert!(false);
	}
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_num_and_htlc_id_increment() {
	//BOLT 2 Requirement: if result would be offering more than the remote's max_accepted_htlcs HTLCs, in the remote commitment transaction: MUST NOT add an HTLC.
	//BOLT 2 Requirement: for the first HTLC it offers MUST set id to 0.
	//BOLT 2 Requirement: MUST increase the value of id by 1 for each successive offer.
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0, LocalFeatures::new(), LocalFeatures::new());
	let max_accepted_htlcs = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().their_max_accepted_htlcs as u64;

	for i in 0..max_accepted_htlcs {
		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
		let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
		let payment_event = {
			nodes[0].node.send_payment(route, our_payment_hash).unwrap();
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
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_payment_received!(nodes[1], our_payment_hash, 100000);
	}
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let err = nodes[0].node.send_payment(route, our_payment_hash);

	if let Err(APIError::ChannelUnavailable{err}) = err {
		assert_eq!(err, "Cannot push more than their max accepted HTLCs");
	} else {
		assert!(false);
	}
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_value_in_flight() {
	//BOLT 2 Requirement: if the sum of total offered HTLCs would exceed the remote's max_htlc_value_in_flight_msat: MUST NOT add an HTLC.
	let mut nodes = create_network(2, &[None, None]);
	let channel_value = 100000;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 0, LocalFeatures::new(), LocalFeatures::new());
	let max_in_flight = get_channel_value_stat!(nodes[0], chan.2).their_max_htlc_value_in_flight_msat;

	send_payment(&nodes[0], &vec!(&nodes[1])[..], max_in_flight);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], max_in_flight+1, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let err = nodes[0].node.send_payment(route, our_payment_hash);

	if let Err(APIError::ChannelUnavailable{err}) = err {
		assert_eq!(err, "Cannot send value that would put us over the max HTLC value in flight our peer will accept");
	} else {
		assert!(false);
	}

	send_payment(&nodes[0], &[&nodes[1]], max_in_flight);
}

// BOLT 2 Requirements for the Receiver when handling an update_add_htlc message.
#[test]
fn test_update_add_htlc_bolt2_receiver_check_amount_received_more_than_min() {
	//BOLT2 Requirement: receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat -> SHOULD fail the channel.
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, LocalFeatures::new(), LocalFeatures::new());
	let htlc_minimum_msat: u64;
	{
		let chan_lock = nodes[0].node.channel_state.lock().unwrap();
		let channel = chan_lock.by_id.get(&chan.2).unwrap();
		htlc_minimum_msat = channel.get_our_htlc_minimum_msat();
	}
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], htlc_minimum_msat, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = htlc_minimum_msat-1;
	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote side tried to send less than our minimum HTLC value");
	} else {
		assert!(false);
	}
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_sender_can_afford_amount_sent() {
	//BOLT2 Requirement: receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw (while maintaining its channel reserve): SHOULD fail the channel
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, LocalFeatures::new(), LocalFeatures::new());

	let their_channel_reserve = get_channel_value_stat!(nodes[0], chan.2).channel_reserve_msat;

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 5000000-their_channel_reserve, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	updates.update_add_htlcs[0].amount_msat = 5000000-their_channel_reserve+1;
	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote HTLC add would put them over their reserve value");
	} else {
		assert!(false);
	}

	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_htlc_limit() {
	//BOLT 2 Requirement: if a sending node adds more than its max_accepted_htlcs HTLCs to its local commitment transaction: SHOULD fail the channel
	//BOLT 2 Requirement: MUST allow multiple HTLCs with the same payment_hash.
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 3999999, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let session_priv = SecretKey::from_slice(&{
		let mut session_key = [0; 32];
		let mut rng = thread_rng();
		rng.fill_bytes(&mut session_key);
		session_key
	}).expect("RNG is bad!");

	let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
	let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::signing_only(), &route, &session_priv).unwrap();
	let (onion_payloads, _htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &our_payment_hash);

	let mut msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 0,
		amount_msat: 1000,
		payment_hash: our_payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet.clone(),
	};

	for i in 0..super::channel::OUR_MAX_HTLCS {
		msg.htlc_id = i as u64;
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg).unwrap();
	}
	msg.htlc_id = (super::channel::OUR_MAX_HTLCS) as u64;
	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to push more than our max accepted HTLCs");
	} else {
		assert!(false);
	}

	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_in_flight_msat() {
	//OR adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction: SHOULD fail the channel
	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = get_channel_value_stat!(nodes[1], chan.2).their_max_htlc_value_in_flight_msat + 1;
	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err,"Remote HTLC add would put them over our max HTLC value");
	} else {
		assert!(false);
	}

	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_cltv_expiry() {
	//BOLT2 Requirement: if sending node sets cltv_expiry to greater or equal to 500000000: SHOULD fail the channel.
	let mut nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 3999999, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].cltv_expiry = 500000000;
	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err,"Remote provided CLTV expiry in seconds instead of block height");
	} else {
		assert!(false);
	}

	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_repeated_id_ignore() {
	//BOLT 2 requirement: if the sender did not previously acknowledge the commitment of that HTLC: MUST ignore a repeated id value after a reconnection.
	// We test this by first testing that that repeated HTLCs pass commitment signature checks
	// after disconnect and that non-sequential htlc_ids result in a channel failure.
	let mut nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();

	//Disconnect and Reconnect
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	//Resend HTLC
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();
	assert_eq!(updates.commitment_signed.htlc_signatures.len(), 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let _bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote skipped HTLC ID");
	} else {
		assert!(false);
	}

	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fulfill_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();

	let update_msg = msgs::UpdateFulfillHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		payment_preimage: our_payment_preimage,
	};

	let err = nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to fulfill/fail HTLC before it had been committed");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();

	let update_msg = msgs::UpdateFailHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		reason: msgs::OnionErrorPacket { data: Vec::new()},
	};

	let err = nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to fulfill/fail HTLC before it had been committed");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_malformed_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let mut nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();

	let update_msg = msgs::UpdateFailMalformedHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		sha256_of_onion: [1; 32],
		failure_code: 0x8000,
	};

	let err = nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to fulfill/fail HTLC before it had been committed");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_incorrect_htlc_id() {
	//BOLT 2 Requirement: A receiving node:	if the id does not correspond to an HTLC in its current commitment transaction MUST fail the channel.

	let nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let our_payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 100000).0;

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);

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

	let err = nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);
	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to fulfill/fail an HTLC we couldn't find");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_wrong_preimage() {
	//BOLT 2 Requirement: A receiving node:	if the payment_preimage value in update_fulfill_htlc doesn't SHA256 hash to the corresponding HTLC payment_hash	MUST fail the channel.

	let nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let our_payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 100000).0;

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);

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

	let err = nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);
	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Remote tried to fulfill HTLC with an incorrect preimage");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}


#[test]
fn test_update_fulfill_htlc_bolt2_missing_badonion_bit_for_malformed_htlc_message() {
	//BOLT 2 Requirement: A receiving node: if the BADONION bit in failure_code is not set for update_fail_malformed_htlc MUST fail the channel.

	let mut nodes = create_network(2, &[None, None]);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, LocalFeatures::new(), LocalFeatures::new());
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();
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
	let err = nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);
	if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::SendErrorMessage {..})}) = err {
		assert_eq!(err, "Got update_fail_malformed_htlc with BADONION not set");
	} else {
		assert!(false);
	}

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0]);
}

#[test]
fn test_update_fulfill_htlc_bolt2_after_malformed_htlc_message_must_forward_update_fail_htlc() {
	//BOLT 2 Requirement: a receiving node which has an outgoing HTLC canceled by update_fail_malformed_htlc:
	//    * MUST return an error in the update_fail_htlc sent to the link which originally sent the HTLC, using the failure_code given and setting the data to sha256_of_onion.

	let mut nodes = create_network(3, &[None, None, None]);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, LocalFeatures::new(), LocalFeatures::new());
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1000000, 1000000, LocalFeatures::new(), LocalFeatures::new());

	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 100000, TEST_FINAL_CLTV).unwrap();
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	//First hop
	let mut payment_event = {
		nodes[0].node.send_payment(route, our_payment_hash).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
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
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
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

	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), &update_msg.0).unwrap();

	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[2], update_msg.1, false, true);
	expect_pending_htlcs_forwardable!(nodes[1]);
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

fn do_test_failure_delay_dust_htlc_local_commitment(announce_latest: bool) {
	// Dust-HTLC failure updates must be delayed until failure-trigger tx (in this case local commitment) reach ANTI_REORG_DELAY
	// We can have at most two valid local commitment tx, so both cases must be covered, and both txs must be checked to get them all as
	// HTLC could have been removed from lastest local commitment tx but still valid until we get remote RAA

	let nodes = create_network(2, &[None, None]);
	let chan =create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let bs_dust_limit = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().our_dust_limit_satoshis;

	// We route 2 dust-HTLCs between A and B
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_, payment_hash_2) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Cache one local commitment tx as previous
	let as_prev_commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();

	// Fail one HTLC to prune it in the will-be-latest-local commitment tx
	assert!(nodes[1].node.fail_htlc_backwards(&payment_hash_2));
	check_added_monitors!(nodes[1], 0);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let remove = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &remove.update_fail_htlcs[0]).unwrap();
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &remove.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);

	// Cache one local commitment tx as lastest
	let as_last_commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();

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
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	if announce_latest {
		nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&as_last_commitment_tx[0]], &[1; 1]);
	} else {
		nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&as_prev_commitment_tx[0]], &[1; 1]);
	}

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	connect_blocks(&nodes[0].chain_monitor, ANTI_REORG_DELAY - 1, 1, true,  header.bitcoin_hash());
	let events = nodes[0].node.get_and_clear_pending_events();
	// Only 2 PaymentFailed events should show up, over-dust HTLC has to be failed by timeout tx
	assert_eq!(events.len(), 2);
	let mut first_failed = false;
	for event in events {
		match event {
			Event::PaymentFailed { payment_hash, .. } => {
				if payment_hash == payment_hash_1 {
					assert!(!first_failed);
					first_failed = true;
				} else {
					assert_eq!(payment_hash, payment_hash_2);
				}
			}
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_failure_delay_dust_htlc_local_commitment() {
	do_test_failure_delay_dust_htlc_local_commitment(true);
	do_test_failure_delay_dust_htlc_local_commitment(false);
}

#[test]
fn test_no_failure_dust_htlc_local_commitment() {
	// Transaction filters for failing back dust htlc based on local commitment txn infos has been
	// prone to error, we test here that a dummy transaction don't fail them.

	let nodes = create_network(2, &[None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	// Rebalance a bit
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	let as_dust_limit = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().our_dust_limit_satoshis;
	let bs_dust_limit = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().our_dust_limit_satoshis;

	// We route 2 dust-HTLCs between A and B
	let (preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (preimage_2, _) = route_payment(&nodes[1], &[&nodes[0]], as_dust_limit*1000);

	// Build a dummy invalid transaction trying to spend a commitment tx
	let input = TxIn {
		previous_output: BitcoinOutPoint { txid: chan.3.txid(), vout: 0 },
		script_sig: Script::new(),
		sequence: 0,
		witness: Vec::new(),
	};

	let outp = TxOut {
		script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
		value: 10000,
	};

	let dummy_tx = Transaction {
		version: 2,
		lock_time: 0,
		input: vec![input],
		output: vec![outp]
	};

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	nodes[0].chan_monitor.simple_monitor.block_connected(&header, 1, &[&dummy_tx], &[1;1]);
	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 0);
	// We broadcast a few more block to check everything is all right
	connect_blocks(&nodes[0].chain_monitor, 20, 1, true,  header.bitcoin_hash());
	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 0);

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], preimage_1);
	claim_payment(&nodes[1], &vec!(&nodes[0])[..], preimage_2);
}

fn do_test_sweep_outbound_htlc_failure_update(revoked: bool, local: bool) {
	// Outbound HTLC-failure updates must be cancelled if we get a reorg before we reach ANTI_REORG_DELAY.
	// Broadcast of revoked remote commitment tx, trigger failure-update of dust/non-dust HTLCs
	// Broadcast of remote commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of timeout tx on remote commitment tx, trigger failure-udate of non-dust HTLCs
	// Broadcast of local commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of HTLC-timeout tx on local commitment tx, trigger failure-update of non-dust HTLCs

	let nodes = create_network(3, &[None, None, None]);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, LocalFeatures::new(), LocalFeatures::new());

	let bs_dust_limit = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().our_dust_limit_satoshis;

	let (_payment_preimage_1, dust_hash) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_payment_preimage_2, non_dust_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	let as_commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();
	let bs_commitment_tx = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();

	// We revoked bs_commitment_tx
	if revoked {
		let (payment_preimage_3, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);
	}

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	let mut timeout_tx = Vec::new();
	if local {
		// We fail dust-HTLC 1 by broadcast of local commitment tx
		nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&as_commitment_tx[0]], &[1; 1]);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		let parent_hash  = connect_blocks(&nodes[0].chain_monitor, ANTI_REORG_DELAY - 1, 2, true, header.bitcoin_hash());
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, dust_hash);
			},
			_ => panic!("Unexpected event"),
		}
		assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		// We fail non-dust-HTLC 2 by broadcast of local HTLC-timeout tx on local commitment tx
		let header_2 = BlockHeader { version: 0x20000000, prev_blockhash: parent_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		nodes[0].chain_monitor.block_connected_checked(&header_2, 7, &[&timeout_tx[0]], &[1; 1]);
		let header_3 = BlockHeader { version: 0x20000000, prev_blockhash: header_2.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_blocks(&nodes[0].chain_monitor, ANTI_REORG_DELAY - 1, 8, true, header_3.bitcoin_hash());
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, non_dust_hash);
			},
			_ => panic!("Unexpected event"),
		}
	} else {
		// We fail dust-HTLC 1 by broadcast of remote commitment tx. If revoked, fail also non-dust HTLC
		nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&bs_commitment_tx[0]], &[1; 1]);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		let parent_hash  = connect_blocks(&nodes[0].chain_monitor, ANTI_REORG_DELAY - 1, 2, true, header.bitcoin_hash());
		let header_2 = BlockHeader { version: 0x20000000, prev_blockhash: parent_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		if !revoked {
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { payment_hash, .. } => {
					assert_eq!(payment_hash, dust_hash);
				},
				_ => panic!("Unexpected event"),
			}
			assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
			// We fail non-dust-HTLC 2 by broadcast of local timeout tx on remote commitment tx
			nodes[0].chain_monitor.block_connected_checked(&header_2, 7, &[&timeout_tx[0]], &[1; 1]);
			assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
			let header_3 = BlockHeader { version: 0x20000000, prev_blockhash: header_2.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			connect_blocks(&nodes[0].chain_monitor, ANTI_REORG_DELAY - 1, 8, true, header_3.bitcoin_hash());
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { payment_hash, .. } => {
					assert_eq!(payment_hash, non_dust_hash);
				},
				_ => panic!("Unexpected event"),
			}
		} else {
			// If revoked, both dust & non-dust HTLCs should have been failed after ANTI_REORG_DELAY confs of revoked
			// commitment tx
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 2);
			let first;
			match events[0] {
				Event::PaymentFailed { payment_hash, .. } => {
					if payment_hash == dust_hash { first = true; }
					else { first = false; }
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { payment_hash, .. } => {
					if first { assert_eq!(payment_hash, non_dust_hash); }
					else { assert_eq!(payment_hash, dust_hash); }
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

#[test]
fn test_sweep_outbound_htlc_failure_update() {
	do_test_sweep_outbound_htlc_failure_update(false, true);
	do_test_sweep_outbound_htlc_failure_update(false, false);
	do_test_sweep_outbound_htlc_failure_update(true, false);
}

#[test]
fn test_upfront_shutdown_script() {
	// BOLT 2 : Option upfront shutdown script, if peer commit its closing_script at channel opening
	// enforce it at shutdown message

	let mut config = UserConfig::new();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let nodes = create_network(3, &[None, Some(config), None]);

	// We test that in case of peer committing upfront to a script, if it changes at closing, we refuse to sign
	let flags = LocalFeatures::new();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint::new(chan.3.txid(), 0).to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	// Test we enforce upfront_scriptpbukey if by providing a diffrent one at closing that  we disconnect peer
	if let Err(error) = nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown) {
		if let Some(error) = error.action {
			match error {
				ErrorAction::SendErrorMessage { msg } => {
					assert_eq!(msg.data,"Got shutdown request with a scriptpubkey which did not match their previous scriptpubkey");
				},
				_ => { assert!(false); }
			}
		} else { assert!(false); }
	} else { assert!(false); }
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// We test that in case of peer committing upfront to a script, if it doesn't change at closing, we sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint::new(chan.3.txid(), 0).to_channel_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	// We test that in case of peer committing upfront to a script, if it oesn't change at closing, we sign
	if let Ok(_) = nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown) {}
	else { assert!(false) }
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if case of peer non-signaling we don't enforce committed script at channel opening
	let mut flags_no = LocalFeatures::new();
	flags_no.unset_upfront_shutdown_script();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags_no, flags.clone());
	nodes[0].node.close_channel(&OutPoint::new(chan.3.txid(), 0).to_channel_id()).unwrap();
	let mut node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	node_1_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	if let Ok(_) = nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_1_shutdown) {}
	else { assert!(false) }
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	// channel smoothly, opt-out is from channel initiator here
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint::new(chan.3.txid(), 0).to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	if let Ok(_) = nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown) {}
	else { assert!(false) }
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	//// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	//// channel smoothly
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint::new(chan.3.txid(), 0).to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	if let Ok(_) = nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown) {}
	else { assert!(false) }
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_user_configurable_csv_delay() {
	// We test our channel constructors yield errors when we pass them absurd csv delay

	let mut low_our_to_self_config = UserConfig::new();
	low_our_to_self_config.own_channel_config.our_to_self_delay = 6;
	let mut high_their_to_self_config = UserConfig::new();
	high_their_to_self_config.peer_channel_config_limits.their_to_self_delay = 100;
	let nodes = create_network(2, &[Some(high_their_to_self_config.clone()), None]);

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in Channel::new_outbound()
	let keys_manager: Arc<KeysInterface> = Arc::new(KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new()), 10, 20));
	if let Err(error) = Channel::new_outbound(&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &keys_manager, nodes[1].node.get_our_node_id(), 1000000, 1000000, 0, Arc::new(test_utils::TestLogger::new()), &low_our_to_self_config) {
		match error {
			APIError::APIMisuseError { err } => { assert_eq!(err, "Configured with an unreasonable our_to_self_delay putting user funds at risks"); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false) }

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in Channel::new_from_req()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.to_self_delay = 200;
	if let Err(error) = Channel::new_from_req(&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &keys_manager, nodes[1].node.get_our_node_id(), LocalFeatures::new(), &open_channel, 0, Arc::new(test_utils::TestLogger::new()), &low_our_to_self_config) {
		match error {
			ChannelError::Close(err) => { assert_eq!(err, "Configured with an unreasonable our_to_self_delay putting user funds at risks"); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Chanel::accept_channel()
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1000000, 1000000, 42).unwrap();
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), LocalFeatures::new(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id())).unwrap();
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	accept_channel.to_self_delay = 200;
	if let Err(error) = nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), LocalFeatures::new(), &accept_channel) {
		if let Some(error) = error.action {
			match error {
				ErrorAction::SendErrorMessage { msg } => {
					assert_eq!(msg.data,"They wanted our payments to be delayed by a needlessly long period");
				},
				_ => { assert!(false); }
			}
		} else { assert!(false); }
	} else { assert!(false); }

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Channel::new_from_req()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.to_self_delay = 200;
	if let Err(error) = Channel::new_from_req(&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &keys_manager, nodes[1].node.get_our_node_id(), LocalFeatures::new(), &open_channel, 0, Arc::new(test_utils::TestLogger::new()), &high_their_to_self_config) {
		match error {
			ChannelError::Close(err) => { assert_eq!(err, "They wanted our payments to be delayed by a needlessly long period"); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }
}

#[test]
fn test_data_loss_protect() {
	// We want to be sure that :
	// * we don't broadcast our Local Commitment Tx in case of fallen behind
	// * we close channel in case of detecting other being fallen behind
	// * we are able to claim our own outputs thanks to remote my_current_per_commitment_point
	let mut nodes = create_network(2, &[None, None]);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, LocalFeatures::new(), LocalFeatures::new());

	// Cache node A state before any channel update
	let previous_node_state = nodes[0].node.encode();
	let mut previous_chan_monitor_state = test_utils::TestVecWriter(Vec::new());
	nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut previous_chan_monitor_state).unwrap();

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// Restore node A from previous state
	let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::with_id(format!("node {}", 0)));
	let chan_monitor = <(Sha256dHash, ChannelMonitor)>::read(&mut ::std::io::Cursor::new(previous_chan_monitor_state.0), Arc::clone(&logger)).unwrap().1;
	let chain_monitor = Arc::new(ChainWatchInterfaceUtil::new(Network::Testnet, Arc::clone(&logger)));
	let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())});
	let feeest = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
	let monitor = Arc::new(test_utils::TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone(), logger.clone(), feeest.clone()));
	let mut channel_monitors = HashMap::new();
	channel_monitors.insert(OutPoint { txid: chan.3.txid(), index: 0 }, &chan_monitor);
	let node_state_0 = <(Sha256dHash, ChannelManager)>::read(&mut ::std::io::Cursor::new(previous_node_state), ChannelManagerReadArgs {
		keys_manager: Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::clone(&logger), 42, 21)),
		fee_estimator: feeest.clone(),
		monitor: monitor.clone(),
		chain_monitor: chain_monitor.clone(),
		logger: Arc::clone(&logger),
		tx_broadcaster,
		default_config: UserConfig::new(),
		channel_monitors: &channel_monitors
	}).unwrap().1;
	nodes[0].node = Arc::new(node_state_0);
	monitor.add_update_monitor(OutPoint { txid: chan.3.txid(), index: 0 }, chan_monitor.clone()).is_ok();
	nodes[0].chan_monitor = monitor;
	nodes[0].chain_monitor = chain_monitor;
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	let reestablish_0 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	// Check we update monitor following learning of per_commitment_point from B
	if let Err(err) = nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_0[0])  {
		if let Some(error) = err.action {
			match error {
				ErrorAction::SendErrorMessage { msg } => {
					assert_eq!(msg.data, "We have fallen behind - we have received proof that if we broadcast remote is going to claim our funds - we can't do any automated broadcasting");
				},
				_ => panic!("Unexpected event!"),
			}
		} else { assert!(false); }
	} else { assert!(false); }
	check_added_monitors!(nodes[0], 1);

	{
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		assert_eq!(node_txn.len(), 0);
	}

	let mut reestablish_1 = Vec::with_capacity(1);
	for msg in nodes[0].node.get_and_clear_pending_msg_events() {
		if let MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } = msg {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			reestablish_1.push(msg.clone());
		} else if let MessageSendEvent::BroadcastChannelUpdate { .. } = msg {
		} else {
			panic!("Unexpected event")
		}
	}

	// Check we close channel detecting A is fallen-behind
	if let Err(err) = nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]) {
		if let Some(error) = err.action {
			match error {
				ErrorAction::SendErrorMessage { msg } => {
					assert_eq!(msg.data, "Peer attempted to reestablish channel with a very old local commitment transaction"); },
				_ => panic!("Unexpected event!"),
			}
		} else { assert!(false); }
	} else { assert!(false); }

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Check A is able to claim to_remote output
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3.clone());
	assert_eq!(node_txn[0].output.len(), 2);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()]}, 1);
	let spend_txn = check_spendable_outputs!(nodes[0], 1);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0].clone());
}
