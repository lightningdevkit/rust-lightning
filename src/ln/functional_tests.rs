//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use chain::chaininterface;
use chain::transaction::OutPoint;
use chain::chaininterface::{ChainListener, ChainWatchInterface};
use chain::keysinterface::{KeysInterface, SpendableOutputDescriptor};
use chain::keysinterface;
use ln::channel::{COMMITMENT_TX_BASE_WEIGHT, COMMITMENT_TX_WEIGHT_PER_HTLC};
use ln::channelmanager::{ChannelManager,ChannelManagerReadArgs,HTLCForwardInfo,RAACommitmentOrder, PaymentPreimage, PaymentHash};
use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, CLTV_CLAIM_BUFFER, HTLC_FAIL_TIMEOUT_BLOCKS, ManyChannelMonitor};
use ln::channel::{ACCEPTED_HTLC_SCRIPT_WEIGHT, OFFERED_HTLC_SCRIPT_WEIGHT};
use ln::onion_utils;
use ln::router::{Route, RouteHop, Router};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler,HTLCFailChannelUpdate};
use util::test_utils;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::logger::Logger;
use util::ser::{Writeable, Writer, ReadableArgs};
use util::config::UserConfig;

use bitcoin::util::hash::{BitcoinHash, Sha256dHash};
use bitcoin::util::bip143;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey, ExtendedPrivKey};
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, SigHashType};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;

use secp256k1::{Secp256k1, Message};
use secp256k1::key::{PublicKey,SecretKey};

use rand::{thread_rng,Rng};

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::default::Default;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::mem;

fn confirm_transaction(chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction, chan_id: u32) {
	assert!(chain.does_match_tx(tx));
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain.block_connected_checked(&header, 1, &[tx; 1], &[chan_id; 1]);
	for i in 2..100 {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		chain.block_connected_checked(&header, i, &[tx; 0], &[0; 0]);
	}
}

struct Node {
	chain_monitor: Arc<chaininterface::ChainWatchInterfaceUtil>,
	tx_broadcaster: Arc<test_utils::TestBroadcaster>,
	chan_monitor: Arc<test_utils::TestChannelMonitor>,
	keys_manager: Arc<test_utils::TestKeysInterface>,
	node: Arc<ChannelManager>,
	router: Router,
	node_seed: [u8; 32],
	network_payment_count: Rc<RefCell<u8>>,
	network_chan_count: Rc<RefCell<u32>>,
}
impl Drop for Node {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Check that we processed all pending events
			assert!(self.node.get_and_clear_pending_msg_events().is_empty());
			assert!(self.node.get_and_clear_pending_events().is_empty());
			assert!(self.chan_monitor.added_monitors.lock().unwrap().is_empty());
		}
	}
}

fn create_chan_between_nodes(node_a: &Node, node_b: &Node) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001)
}

fn create_chan_between_nodes_with_value(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(node_a, node_b, &funding_locked);
	(announcement, as_update, bs_update, channel_id, tx)
}

macro_rules! get_revoke_commit_msgs {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 2);
			(match events[0] {
				MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
					assert_eq!(*node_id, $node_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			}, match events[1] {
				MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
					assert_eq!(*node_id, $node_id);
					assert!(updates.update_add_htlcs.is_empty());
					assert!(updates.update_fulfill_htlcs.is_empty());
					assert!(updates.update_fail_htlcs.is_empty());
					assert!(updates.update_fail_malformed_htlcs.is_empty());
					assert!(updates.update_fee.is_none());
					updates.commitment_signed.clone()
				},
				_ => panic!("Unexpected event"),
			})
		}
	}
}

macro_rules! get_event_msg {
	($node: expr, $event_type: path, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$event_type { ref node_id, ref msg } => {
					assert_eq!(*node_id, $node_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

macro_rules! get_htlc_update_msgs {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
					assert_eq!(*node_id, $node_id);
					(*updates).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

macro_rules! get_feerate {
	($node: expr, $channel_id: expr) => {
		{
			let chan_lock = $node.node.channel_state.lock().unwrap();
			let chan = chan_lock.by_id.get(&$channel_id).unwrap();
			chan.get_feerate()
		}
	}
}


fn create_chan_between_nodes_with_value_init(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> Transaction {
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42).unwrap();
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id())).unwrap();
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id())).unwrap();

	let chan_id = *node_a.network_chan_count.borrow();
	let tx;
	let funding_output;

	let events_2 = node_a.node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(*channel_value_satoshis, channel_value);
			assert_eq!(user_channel_id, 42);

			tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
				value: *channel_value_satoshis, script_pubkey: output_script.clone(),
			}]};
			funding_output = OutPoint::new(tx.txid(), 0);

			node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
			let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			assert_eq!(added_monitors[0].0, funding_output);
			added_monitors.clear();
		},
		_ => panic!("Unexpected event"),
	}

	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id())).unwrap();
	{
		let mut added_monitors = node_b.chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id())).unwrap();
	{
		let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	let events_4 = node_a.node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	tx
}

fn create_chan_between_nodes_with_value_confirm(node_a: &Node, node_b: &Node, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	confirm_transaction(&node_b.chain_monitor, &tx, tx.version);
	node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingLocked, node_a.node.get_our_node_id())).unwrap();

	let channel_id;

	confirm_transaction(&node_a.chain_monitor, &tx, tx.version);
	let events_6 = node_a.node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 2);
	((match events_6[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
			channel_id = msg.channel_id.clone();
			assert_eq!(*node_id, node_b.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}, match events_6[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_b.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}), channel_id)
}

fn create_chan_between_nodes_with_value_a(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

fn create_chan_between_nodes_with_value_b(node_a: &Node, node_b: &Node, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
	node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &as_funding_msgs.0).unwrap();
	let bs_announcement_sigs = get_event_msg!(node_b, MessageSendEvent::SendAnnouncementSignatures, node_a.node.get_our_node_id());
	node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_funding_msgs.1).unwrap();

	let events_7 = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(events_7.len(), 1);
	let (announcement, bs_update) = match events_7[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg, update_msg)
		},
		_ => panic!("Unexpected event"),
	};

	node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &bs_announcement_sigs).unwrap();
	let events_8 = node_a.node.get_and_clear_pending_msg_events();
	assert_eq!(events_8.len(), 1);
	let as_update = match events_8[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			assert!(*announcement == *msg);
			assert_eq!(update_msg.contents.short_channel_id, announcement.contents.short_channel_id);
			assert_eq!(update_msg.contents.short_channel_id, bs_update.contents.short_channel_id);
			update_msg
		},
		_ => panic!("Unexpected event"),
	};

	*node_a.network_chan_count.borrow_mut() += 1;

	((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
}

fn create_announced_chan_between_nodes(nodes: &Vec<Node>, a: usize, b: usize) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001)
}

fn create_announced_chan_between_nodes_with_value(nodes: &Vec<Node>, a: usize, b: usize, channel_value: u64, push_msat: u64) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat);
	for node in nodes {
		assert!(node.router.handle_channel_announcement(&chan_announcement.0).unwrap());
		node.router.handle_channel_update(&chan_announcement.1).unwrap();
		node.router.handle_channel_update(&chan_announcement.2).unwrap();
	}
	(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
}

macro_rules! check_spends {
	($tx: expr, $spends_tx: expr) => {
		{
			let mut funding_tx_map = HashMap::new();
			let spends_tx = $spends_tx;
			funding_tx_map.insert(spends_tx.txid(), spends_tx);
			$tx.verify(&funding_tx_map).unwrap();
		}
	}
}

macro_rules! get_closing_signed_broadcast {
	($node: expr, $dest_pubkey: expr) => {
		{
			let events = $node.get_and_clear_pending_msg_events();
			assert!(events.len() == 1 || events.len() == 2);
			(match events[events.len() - 1] {
				MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
					assert_eq!(msg.contents.flags & 2, 2);
					msg.clone()
				},
				_ => panic!("Unexpected event"),
			}, if events.len() == 2 {
				match events[0] {
					MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
						assert_eq!(*node_id, $dest_pubkey);
						Some(msg.clone())
					},
					_ => panic!("Unexpected event"),
				}
			} else { None })
		}
	}
}

macro_rules! check_closed_broadcast {
	($node: expr) => {{
		let events = $node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
	}}
}

fn close_channel(outbound_node: &Node, inbound_node: &Node, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
	let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
	let (node_b, broadcaster_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster) } else { (&inbound_node.node, &inbound_node.tx_broadcaster) };
	let (tx_a, tx_b);

	node_a.close_channel(channel_id).unwrap();
	node_b.handle_shutdown(&node_a.get_our_node_id(), &get_event_msg!(struct_a, MessageSendEvent::SendShutdown, node_b.get_our_node_id())).unwrap();

	let events_1 = node_b.get_and_clear_pending_msg_events();
	assert!(events_1.len() >= 1);
	let shutdown_b = match events_1[0] {
		MessageSendEvent::SendShutdown { ref node_id, ref msg } => {
			assert_eq!(node_id, &node_a.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	let closing_signed_b = if !close_inbound_first {
		assert_eq!(events_1.len(), 1);
		None
	} else {
		Some(match events_1[1] {
			MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
				assert_eq!(node_id, &node_a.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		})
	};

	node_a.handle_shutdown(&node_b.get_our_node_id(), &shutdown_b).unwrap();
	let (as_update, bs_update) = if close_inbound_first {
		assert!(node_a.get_and_clear_pending_msg_events().is_empty());
		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap()).unwrap();
		let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
		assert!(none_b.is_none());
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		(as_update, bs_update)
	} else {
		let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a).unwrap();
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
		let (as_update, none_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());
		assert!(none_a.is_none());
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		(as_update, bs_update)
	};
	assert_eq!(tx_a, tx_b);
	check_spends!(tx_a, funding_tx);

	(as_update, bs_update, tx_a)
}

struct SendEvent {
	node_id: PublicKey,
	msgs: Vec<msgs::UpdateAddHTLC>,
	commitment_msg: msgs::CommitmentSigned,
}
impl SendEvent {
	fn from_commitment_update(node_id: PublicKey, updates: msgs::CommitmentUpdate) -> SendEvent {
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		SendEvent { node_id: node_id, msgs: updates.update_add_htlcs, commitment_msg: updates.commitment_signed }
	}

	fn from_event(event: MessageSendEvent) -> SendEvent {
		match event {
			MessageSendEvent::UpdateHTLCs { node_id, updates } => SendEvent::from_commitment_update(node_id, updates),
			_ => panic!("Unexpected event type!"),
		}
	}

	fn from_node(node: &Node) -> SendEvent {
		let mut events = node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.pop().unwrap())
	}
}

macro_rules! check_added_monitors {
	($node: expr, $count: expr) => {
		{
			let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), $count);
			added_monitors.clear();
		}
	}
}

macro_rules! commitment_signed_dance {
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */) => {
		{
			check_added_monitors!($node_a, 0);
			assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed).unwrap();
			check_added_monitors!($node_a, 1);
			commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, false);
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */, true /* return last RAA */) => {
		{
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!($node_a, $node_b.node.get_our_node_id());
			check_added_monitors!($node_b, 0);
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			$node_b.node.handle_revoke_and_ack(&$node_a.node.get_our_node_id(), &as_revoke_and_ack).unwrap();
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors!($node_b, 1);
			$node_b.node.handle_commitment_signed(&$node_a.node.get_our_node_id(), &as_commitment_signed).unwrap();
			let (bs_revoke_and_ack, extra_msg_option) = {
				let events = $node_b.node.get_and_clear_pending_msg_events();
				assert!(events.len() <= 2);
				(match events[0] {
					MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $node_a.node.get_our_node_id());
						(*msg).clone()
					},
					_ => panic!("Unexpected event"),
				}, events.get(1).map(|e| e.clone()))
			};
			check_added_monitors!($node_b, 1);
			if $fail_backwards {
				assert!($node_a.node.get_and_clear_pending_events().is_empty());
				assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			}
			(extra_msg_option, bs_revoke_and_ack)
		}
	};
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */, false /* return extra message */, true /* return last RAA */) => {
		{
			check_added_monitors!($node_a, 0);
			assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed).unwrap();
			check_added_monitors!($node_a, 1);
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			assert!(extra_msg_option.is_none());
			bs_revoke_and_ack
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */) => {
		{
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			$node_a.node.handle_revoke_and_ack(&$node_b.node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
			check_added_monitors!($node_a, 1);
			extra_msg_option
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, false /* no extra message */) => {
		{
			assert!(commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true).is_none());
		}
	};
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr) => {
		{
			commitment_signed_dance!($node_a, $node_b, $commitment_signed, $fail_backwards, true);
			if $fail_backwards {
				expect_pending_htlcs_forwardable!($node_a);
				check_added_monitors!($node_a, 1);

				let channel_state = $node_a.node.channel_state.lock().unwrap();
				assert_eq!(channel_state.pending_msg_events.len(), 1);
				if let MessageSendEvent::UpdateHTLCs { ref node_id, .. } = channel_state.pending_msg_events[0] {
					assert_ne!(*node_id, $node_b.node.get_our_node_id());
				} else { panic!("Unexpected event"); }
			} else {
				assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			}
		}
	}
}

macro_rules! get_payment_preimage_hash {
	($node: expr) => {
		{
			let payment_preimage = PaymentPreimage([*$node.network_payment_count.borrow(); 32]);
			*$node.network_payment_count.borrow_mut() += 1;
			let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
			(payment_preimage, payment_hash)
		}
	}
}

macro_rules! expect_pending_htlcs_forwardable {
	($node: expr) => {{
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		let node_ref: &Node = &$node;
		node_ref.node.channel_state.lock().unwrap().next_forward = Instant::now();
		$node.node.process_pending_htlc_forwards();
	}}
}

fn send_along_route_with_hash(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64, our_payment_hash: PaymentHash) {
	let mut payment_event = {
		origin_node.node.send_payment(route, our_payment_hash).unwrap();
		check_added_monitors!(origin_node, 1);

		let mut events = origin_node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	let mut prev_node = origin_node;

	for (idx, &node) in expected_route.iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(node);

		if idx == expected_route.len() - 1 {
			let events_2 = node.node.get_and_clear_pending_events();
			assert_eq!(events_2.len(), 1);
			match events_2[0] {
				Event::PaymentReceived { ref payment_hash, amt } => {
					assert_eq!(our_payment_hash, *payment_hash);
					assert_eq!(amt, recv_value);
				},
				_ => panic!("Unexpected event"),
			}
		} else {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors!(node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		}

		prev_node = node;
	}
}

fn send_along_route(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	send_along_route_with_hash(origin_node, route, expected_route, recv_value, our_payment_hash);
	(our_payment_preimage, our_payment_hash)
}

fn claim_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_preimage: PaymentPreimage) {
	assert!(expected_route.last().unwrap().node.claim_funds(our_payment_preimage));
	check_added_monitors!(expected_route.last().unwrap(), 1);

	let mut next_msgs: Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)> = None;
	let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
	macro_rules! get_next_msgs {
		($node: expr) => {
			{
				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
						assert!(update_add_htlcs.is_empty());
						assert_eq!(update_fulfill_htlcs.len(), 1);
						assert!(update_fail_htlcs.is_empty());
						assert!(update_fail_malformed_htlcs.is_empty());
						assert!(update_fee.is_none());
						expected_next_node = node_id.clone();
						Some((update_fulfill_htlcs[0].clone(), commitment_signed.clone()))
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	}

	macro_rules! last_update_fulfill_dance {
		($node: expr, $prev_node: expr) => {
			{
				$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
				check_added_monitors!($node, 0);
				assert!($node.node.get_and_clear_pending_msg_events().is_empty());
				commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
			}
		}
	}
	macro_rules! mid_update_fulfill_dance {
		($node: expr, $prev_node: expr, $new_msgs: expr) => {
			{
				$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
				check_added_monitors!($node, 1);
				let new_next_msgs = if $new_msgs {
					get_next_msgs!($node)
				} else {
					assert!($node.node.get_and_clear_pending_msg_events().is_empty());
					None
				};
				commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
				next_msgs = new_next_msgs;
			}
		}
	}

	let mut prev_node = expected_route.last().unwrap();
	for (idx, node) in expected_route.iter().rev().enumerate() {
		assert_eq!(expected_next_node, node.node.get_our_node_id());
		let update_next_msgs = !skip_last || idx != expected_route.len() - 1;
		if next_msgs.is_some() {
			mid_update_fulfill_dance!(node, prev_node, update_next_msgs);
		} else if update_next_msgs {
			next_msgs = get_next_msgs!(node);
		} else {
			assert!(node.node.get_and_clear_pending_msg_events().is_empty());
		}
		if !skip_last && idx == expected_route.len() - 1 {
			assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
		}

		prev_node = node;
	}

	if !skip_last {
		last_update_fulfill_dance!(origin_node, expected_route.first().unwrap());
		let events = origin_node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { payment_preimage } => {
				assert_eq!(payment_preimage, our_payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

fn claim_payment(origin_node: &Node, expected_route: &[&Node], our_payment_preimage: PaymentPreimage) {
	claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage);
}

const TEST_FINAL_CLTV: u32 = 32;

fn route_payment(origin_node: &Node, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.hops.len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	send_along_route(origin_node, route, expected_route, recv_value)
}

fn route_over_limit(origin_node: &Node, expected_route: &[&Node], recv_value: u64) {
	let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.hops.len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	let (_, our_payment_hash) = get_payment_preimage_hash!(origin_node);

	let err = origin_node.node.send_payment(route, our_payment_hash).err().unwrap();
	match err {
		APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our max HTLC value in flight"),
		_ => panic!("Unknown error variants"),
	};
}

fn send_payment(origin: &Node, expected_route: &[&Node], recv_value: u64) {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage);
}

fn fail_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_hash: PaymentHash) {
	assert!(expected_route.last().unwrap().node.fail_htlc_backwards(&our_payment_hash, 0));
	expect_pending_htlcs_forwardable!(expected_route.last().unwrap());
	check_added_monitors!(expected_route.last().unwrap(), 1);

	let mut next_msgs: Option<(msgs::UpdateFailHTLC, msgs::CommitmentSigned)> = None;
	macro_rules! update_fail_dance {
		($node: expr, $prev_node: expr, $last_node: expr) => {
			{
				$node.node.handle_update_fail_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
				commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, !$last_node);
				if skip_last && $last_node {
					expect_pending_htlcs_forwardable!($node);
				}
			}
		}
	}

	let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
	let mut prev_node = expected_route.last().unwrap();
	for (idx, node) in expected_route.iter().rev().enumerate() {
		assert_eq!(expected_next_node, node.node.get_our_node_id());
		if next_msgs.is_some() {
			// We may be the "last node" for the purpose of the commitment dance if we're
			// skipping the last node (implying it is disconnected) and we're the
			// second-to-last node!
			update_fail_dance!(node, prev_node, skip_last && idx == expected_route.len() - 1);
		}

		let events = node.node.get_and_clear_pending_msg_events();
		if !skip_last || idx != expected_route.len() - 1 {
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
					assert!(update_add_htlcs.is_empty());
					assert!(update_fulfill_htlcs.is_empty());
					assert_eq!(update_fail_htlcs.len(), 1);
					assert!(update_fail_malformed_htlcs.is_empty());
					assert!(update_fee.is_none());
					expected_next_node = node_id.clone();
					next_msgs = Some((update_fail_htlcs[0].clone(), commitment_signed.clone()));
				},
				_ => panic!("Unexpected event"),
			}
		} else {
			assert!(events.is_empty());
		}
		if !skip_last && idx == expected_route.len() - 1 {
			assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
		}

		prev_node = node;
	}

	if !skip_last {
		update_fail_dance!(origin_node, expected_route.first().unwrap(), true);

		let events = origin_node.node.get_and_clear_pending_events();
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

fn fail_payment(origin_node: &Node, expected_route: &[&Node], our_payment_hash: PaymentHash) {
	fail_payment_along_route(origin_node, expected_route, false, our_payment_hash);
}

fn create_network(node_count: usize) -> Vec<Node> {
	let mut nodes = Vec::new();
	let mut rng = thread_rng();
	let secp_ctx = Secp256k1::new();

	let chan_count = Rc::new(RefCell::new(0));
	let payment_count = Rc::new(RefCell::new(0));

	for i in 0..node_count {
		let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
		let feeest = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
		let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet, Arc::clone(&logger)));
		let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())});
		let mut seed = [0; 32];
		rng.fill_bytes(&mut seed);
		let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet, Arc::clone(&logger)));
		let chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone(), logger.clone()));
		let mut config = UserConfig::new();
		config.channel_options.announced_channel = true;
		config.channel_limits.force_announced_channel_preference = false;
		let node = ChannelManager::new(Network::Testnet, feeest.clone(), chan_monitor.clone(), chain_monitor.clone(), tx_broadcaster.clone(), Arc::clone(&logger), keys_manager.clone(), config).unwrap();
		let router = Router::new(PublicKey::from_secret_key(&secp_ctx, &keys_manager.get_node_secret()), chain_monitor.clone(), Arc::clone(&logger));
		nodes.push(Node { chain_monitor, tx_broadcaster, chan_monitor, node, router, keys_manager, node_seed: seed,
			network_payment_count: payment_count.clone(),
			network_chan_count: chan_count.clone(),
		});
	}

	nodes
}

#[test]
fn test_async_inbound_update_fee() {
	let mut nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let mut nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let nodes = create_network(2);
	let channel_value = 1888;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 700000);
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
	let mut nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let nodes = create_network(2);
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
	let nodes = create_network(2);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0);
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
	let mut nodes = create_network(3);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
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
	let mut nodes = create_network(3);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

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
	let nodes = create_network(3);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

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
	let nodes = create_network(4);

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
	let chan_5 = create_announced_chan_between_nodes(&nodes, 1, 3);

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
fn duplicate_htlc_test() {
	// Test that we accept duplicate payment_hash HTLCs across the network and that
	// claiming/failing them are all separate and don't effect each other
	let mut nodes = create_network(6);

	// Create some initial channels to route via 3 to 4/5 from 0/1/2
	create_announced_chan_between_nodes(&nodes, 0, 3);
	create_announced_chan_between_nodes(&nodes, 1, 3);
	create_announced_chan_between_nodes(&nodes, 2, 3);
	create_announced_chan_between_nodes(&nodes, 3, 4);
	create_announced_chan_between_nodes(&nodes, 3, 5);

	let (payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], 1000000);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[1], &vec!(&nodes[3])[..], 1000000).0, payment_preimage);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], 1000000).0, payment_preimage);

	claim_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], payment_preimage);
	fail_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], payment_hash);
	claim_payment(&nodes[1], &vec!(&nodes[3])[..], payment_preimage);
}

#[derive(PartialEq)]
enum HTLCType { NONE, TIMEOUT, SUCCESS }
/// Tests that the given node has broadcast transactions for the given Channel
///
/// First checks that the latest local commitment tx has been broadcast, unless an explicit
/// commitment_tx is provided, which may be used to test that a remote commitment tx was
/// broadcast and the revoked outputs were claimed.
///
/// Next tests that there is (or is not) a transaction that spends the commitment transaction
/// that appears to be the type of HTLC transaction specified in has_htlc_tx.
///
/// All broadcast transactions must be accounted for in one of the above three types of we'll
/// also fail.
fn test_txn_broadcast(node: &Node, chan: &(msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction), commitment_tx: Option<Transaction>, has_htlc_tx: HTLCType) -> Vec<Transaction> {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(node_txn.len() >= if commitment_tx.is_some() { 0 } else { 1 } + if has_htlc_tx == HTLCType::NONE { 0 } else { 1 });

	let mut res = Vec::with_capacity(2);
	node_txn.retain(|tx| {
		if tx.input.len() == 1 && tx.input[0].previous_output.txid == chan.3.txid() {
			check_spends!(tx, chan.3.clone());
			if commitment_tx.is_none() {
				res.push(tx.clone());
			}
			false
		} else { true }
	});
	if let Some(explicit_tx) = commitment_tx {
		res.push(explicit_tx.clone());
	}

	assert_eq!(res.len(), 1);

	if has_htlc_tx != HTLCType::NONE {
		node_txn.retain(|tx| {
			if tx.input.len() == 1 && tx.input[0].previous_output.txid == res[0].txid() {
				check_spends!(tx, res[0].clone());
				if has_htlc_tx == HTLCType::TIMEOUT {
					assert!(tx.lock_time != 0);
				} else {
					assert!(tx.lock_time == 0);
				}
				res.push(tx.clone());
				false
			} else { true }
		});
		assert!(res.len() == 2 || res.len() == 3);
		if res.len() == 3 {
			assert_eq!(res[1], res[2]);
		}
	}

	assert!(node_txn.is_empty());
	res
}

/// Tests that the given node has broadcast a claim transaction against the provided revoked
/// HTLC transaction.
fn test_revoked_htlc_claim_txn_broadcast(node: &Node, revoked_tx: Transaction) {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	node_txn.retain(|tx| {
		if tx.input.len() == 1 && tx.input[0].previous_output.txid == revoked_tx.txid() {
			check_spends!(tx, revoked_tx.clone());
			false
		} else { true }
	});
	assert!(node_txn.is_empty());
}

fn check_preimage_claim(node: &Node, prev_txn: &Vec<Transaction>) -> Vec<Transaction> {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();

	assert!(node_txn.len() >= 1);
	assert_eq!(node_txn[0].input.len(), 1);
	let mut found_prev = false;

	for tx in prev_txn {
		if node_txn[0].input[0].previous_output.txid == tx.txid() {
			check_spends!(node_txn[0], tx.clone());
			assert!(node_txn[0].input[0].witness[2].len() > 106); // must spend an htlc output
			assert_eq!(tx.input.len(), 1); // must spend a commitment tx

			found_prev = true;
			break;
		}
	}
	assert!(found_prev);

	let mut res = Vec::new();
	mem::swap(&mut *node_txn, &mut res);
	res
}

fn get_announce_close_broadcast_events(nodes: &Vec<Node>, a: usize, b: usize) {
	let events_1 = nodes[a].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	let as_update = match events_1[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	let events_2 = nodes[b].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let bs_update = match events_2[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	for node in nodes {
		node.router.handle_channel_update(&as_update).unwrap();
		node.router.handle_channel_update(&bs_update).unwrap();
	}
}

fn do_channel_reserve_test(test_recv: bool) {
	use util::rng;
	use std::sync::atomic::Ordering;
	use ln::msgs::HandleError;

	macro_rules! get_channel_value_stat {
		($node: expr, $channel_id: expr) => {{
			let chan_lock = $node.node.channel_state.lock().unwrap();
			let chan = chan_lock.by_id.get(&$channel_id).unwrap();
			chan.get_value_stat()
		}}
	}

	let mut nodes = create_network(3);
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1900, 1001);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1900, 1001);

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

	macro_rules! expect_payment_received {
		($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
			let events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentReceived { ref payment_hash, amt } => {
					assert_eq!($expected_payment_hash, *payment_hash);
					assert_eq!($expected_recv_value, amt);
				},
				_ => panic!("Unexpected event"),
			}
		}
	};

	let feemsat = 239; // somehow we know?
	let total_fee_msat = (nodes.len() - 2) as u64 * 239;

	let recv_value_0 = stat01.their_max_htlc_value_in_flight_msat - total_fee_msat;

	// attempt to send amt_msat > their_max_htlc_value_in_flight_msat
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_0 + 1);
		assert!(route.hops.iter().rev().skip(1).all(|h| h.fee_msat == feemsat));
		let err = nodes[0].node.send_payment(route, our_payment_hash).err().unwrap();
		match err {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our max HTLC value in flight"),
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
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
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
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
			_ => panic!("Unknown error variants"),
		}
	}

	{
		// test channel_reserve test on nodes[1] side
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);

		// Need to manually create update_add_htlc message to go around the channel reserve check in send_htlc()
		let secp_ctx = Secp256k1::new();
		let session_priv = SecretKey::from_slice(&secp_ctx, &{
			let mut session_key = [0; 32];
			rng::fill_bytes(&mut session_key);
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
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
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
fn channel_monitor_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that ChannelMonitor is able to recover from various states.
	let nodes = create_network(5);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4);

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
		for i in 3..TEST_FINAL_CLTV + 2 + HTLC_FAIL_TIMEOUT_BLOCKS + 1 {
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

	let nodes = create_network(2);
	// Create some new channels:
	let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
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
	let nodes = create_network(2);

	// Create some new channel:
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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

		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, payment_hash_2);
			},
			_ => panic!("Unexpected event"),
		}

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 12); // ChannelManager : 2, ChannelMontitor: 8 (1 standard revoked output, 2 revocation htlc tx, 1 local commitment tx + 1 htlc timeout tx) * 2 (block-rescan)

		assert_eq!(node_txn[0], node_txn[7]);
		assert_eq!(node_txn[1], node_txn[8]);
		assert_eq!(node_txn[2], node_txn[9]);
		assert_eq!(node_txn[3], node_txn[10]);
		assert_eq!(node_txn[4], node_txn[11]);
		assert_eq!(node_txn[3], node_txn[5]); //local commitment tx + htlc timeout tx broadcated by ChannelManger
		assert_eq!(node_txn[4], node_txn[6]);

		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);

		let mut revoked_tx_map = HashMap::new();
		revoked_tx_map.insert(revoked_local_txn[0].txid(), revoked_local_txn[0].clone());
		node_txn[0].verify(&revoked_tx_map).unwrap();
		node_txn[1].verify(&revoked_tx_map).unwrap();
		node_txn[2].verify(&revoked_tx_map).unwrap();

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
	// Test that in case of an unilateral close onchain, we detect the state of output thanks to
	// ChainWatchInterface and pass the preimage backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A --------------------> B ----------------------> C (preimage)
	// First, C should claim the HTLC output via HTLC-Success when its own latest local
	// commitment transaction was broadcast.
	// Then, B should learn the preimage from said transactions, attempting to claim backwards
	// towards B.
	// B should be able to claim via preimage if A then broadcasts its local tx.
	// Finally, when A sees B's latest local commitment transaction it should be able to claim
	// the HTLC output via the preimage it learned (which, once confirmed should generate a
	// PaymentSent event).

	let nodes = create_network(3);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (our_payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};

	// Broadcast legit commitment tx from C on B's chain
	// Broadcast HTLC Success transation by C on received output from C's commitment tx on B's chain
	let commitment_tx = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	assert_eq!(commitment_tx.len(), 1);
	check_spends!(commitment_tx[0], chan_2.3.clone());
	nodes[2].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);

	nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2]);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 1 (commitment tx), ChannelMonitor : 2 (2 * HTLC-Success tx)
	assert_eq!(node_txn.len(), 3);
	assert_eq!(node_txn[1], commitment_tx[0]);
	assert_eq!(node_txn[0], node_txn[2]);
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_eq!(node_txn[0].lock_time, 0);

	// Verify that B's ChannelManager is able to extract preimage from HTLC Success tx and pass it backward
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: node_txn}, 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	{
		let mut added_monitors = nodes[1].chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0.txid, chan_1.3.txid());
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
	{
		// nodes[1] now broadcasts its own local state as a fallback, suggesting an alternate
		// commitment transaction with a corresponding HTLC-Timeout transaction, as well as a
		// timeout-claim of the output that nodes[2] just claimed via success.
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap(); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 1 (timeout tx) * 2 (block-rescan)
		assert_eq!(node_txn.len(), 4);
		assert_eq!(node_txn[0], node_txn[3]);
		check_spends!(node_txn[0], commitment_tx[0].clone());
		assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert_ne!(node_txn[0].lock_time, 0);
		assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
		check_spends!(node_txn[1], chan_2.3.clone());
		check_spends!(node_txn[2], node_txn[1].clone());
		assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
		assert_eq!(node_txn[2].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert!(node_txn[2].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
		assert_ne!(node_txn[2].lock_time, 0);
		node_txn.clear();
	}

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
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
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
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { payment_preimage } => {
			assert_eq!(payment_preimage, our_payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 1 (HTLC-Timeout tx) * 2 (block-rescan)
	assert_eq!(node_txn.len(), 4);
	assert_eq!(node_txn[0], node_txn[3]);
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_ne!(node_txn[0].lock_time, 0);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	check_spends!(node_txn[1], chan_1.3.clone());
	check_spends!(node_txn[2], node_txn[1].clone());
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
	assert_eq!(node_txn[2].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert!(node_txn[2].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_ne!(node_txn[2].lock_time, 0);
}

#[test]
fn test_htlc_on_chain_timeout() {
	// Test that in case of an unilateral close onchain, we detect the state of output thanks to
	// ChainWatchInterface and timeout the HTLC  bacward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A ------------------> B ----------------------> C (timeout)
	//    B's commitment tx 		C's commitment tx
	//    	      \                                  \
	//    	   B's HTLC timeout tx		     B's timeout tx

	let nodes = create_network(3);

	// Create some intial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance the network a bit by relaying one payment thorugh all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000);

	let (_payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};

	// Brodacast legit commitment tx from C on B's chain
	let commitment_tx = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	check_spends!(commitment_tx[0], chan_2.3.clone());
	nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
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

	// Broadcast timeout transaction by B on received output fron C's commitment tx on B's chain
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

	let nodes = create_network(3);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().last_local_commitment_txn.clone();
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
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
	let mut nodes = create_network(3);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

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

	assert!(nodes[2].node.fail_htlc_backwards(&first_payment_hash, 0));
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

	assert!(nodes[2].node.fail_htlc_backwards(&second_payment_hash, 0));
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

	assert!(nodes[2].node.fail_htlc_backwards(&third_payment_hash, 0));
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
	nodes[1].node.channel_state.lock().unwrap().next_forward = Instant::now();
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
			// If we delievered B's RAA we got an unknown preimage error, not something
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
	let nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let mut nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

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
		monitors.get_mut(&OutPoint::new(Sha256dHash::from(&payment_event.commitment_msg.channel_id[..]), 0)).unwrap()
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
	let nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

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
	while !headers.is_empty() {
		nodes[0].node.block_disconnected(&headers.pop().unwrap());
	}
	check_closed_broadcast!(nodes[0]);
	let channel_state = nodes[0].node.channel_state.lock().unwrap();
	assert_eq!(channel_state.by_id.len(), 0);
	assert_eq!(channel_state.short_to_id.len(), 0);
}

macro_rules! get_chan_reestablish_msgs {
	($src_node: expr, $dst_node: expr) => {
		{
			let mut res = Vec::with_capacity(1);
			for msg in $src_node.node.get_and_clear_pending_msg_events() {
				if let MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } = msg {
					assert_eq!(*node_id, $dst_node.node.get_our_node_id());
					res.push(msg.clone());
				} else {
					panic!("Unexpected event")
				}
			}
			res
		}
	}
}

macro_rules! handle_chan_reestablish_msgs {
	($src_node: expr, $dst_node: expr) => {
		{
			let msg_events = $src_node.node.get_and_clear_pending_msg_events();
			let mut idx = 0;
			let funding_locked = if let Some(&MessageSendEvent::SendFundingLocked { ref node_id, ref msg }) = msg_events.get(0) {
				idx += 1;
				assert_eq!(*node_id, $dst_node.node.get_our_node_id());
				Some(msg.clone())
			} else {
				None
			};

			let mut revoke_and_ack = None;
			let mut commitment_update = None;
			let order = if let Some(ev) = msg_events.get(idx) {
				idx += 1;
				match ev {
					&MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						revoke_and_ack = Some(msg.clone());
						RAACommitmentOrder::RevokeAndACKFirst
					},
					&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						commitment_update = Some(updates.clone());
						RAACommitmentOrder::CommitmentFirst
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				RAACommitmentOrder::CommitmentFirst
			};

			if let Some(ev) = msg_events.get(idx) {
				match ev {
					&MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						assert!(revoke_and_ack.is_none());
						revoke_and_ack = Some(msg.clone());
					},
					&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						assert!(commitment_update.is_none());
						commitment_update = Some(updates.clone());
					},
					_ => panic!("Unexpected event"),
				}
			}

			(funding_locked, revoke_and_ack, commitment_update, order)
		}
	}
}

/// pending_htlc_adds includes both the holding cell and in-flight update_add_htlcs, whereas
/// for claims/fails they are separated out.
fn reconnect_nodes(node_a: &Node, node_b: &Node, send_funding_locked: (bool, bool), pending_htlc_adds: (i64, i64), pending_htlc_claims: (usize, usize), pending_cell_htlc_claims: (usize, usize), pending_cell_htlc_fails: (usize, usize), pending_raa: (bool, bool)) {
	node_a.node.peer_connected(&node_b.node.get_our_node_id());
	let reestablish_1 = get_chan_reestablish_msgs!(node_a, node_b);
	node_b.node.peer_connected(&node_a.node.get_our_node_id());
	let reestablish_2 = get_chan_reestablish_msgs!(node_b, node_a);

	if send_funding_locked.0 {
		// If a expects a funding_locked, it better not think it has received a revoke_and_ack
		// from b
		for reestablish in reestablish_1.iter() {
			assert_eq!(reestablish.next_remote_commitment_number, 0);
		}
	}
	if send_funding_locked.1 {
		// If b expects a funding_locked, it better not think it has received a revoke_and_ack
		// from a
		for reestablish in reestablish_2.iter() {
			assert_eq!(reestablish.next_remote_commitment_number, 0);
		}
	}
	if send_funding_locked.0 || send_funding_locked.1 {
		// If we expect any funding_locked's, both sides better have set
		// next_local_commitment_number to 1
		for reestablish in reestablish_1.iter() {
			assert_eq!(reestablish.next_local_commitment_number, 1);
		}
		for reestablish in reestablish_2.iter() {
			assert_eq!(reestablish.next_local_commitment_number, 1);
		}
	}

	let mut resp_1 = Vec::new();
	for msg in reestablish_1 {
		node_b.node.handle_channel_reestablish(&node_a.node.get_our_node_id(), &msg).unwrap();
		resp_1.push(handle_chan_reestablish_msgs!(node_b, node_a));
	}
	if pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
		check_added_monitors!(node_b, 1);
	} else {
		check_added_monitors!(node_b, 0);
	}

	let mut resp_2 = Vec::new();
	for msg in reestablish_2 {
		node_a.node.handle_channel_reestablish(&node_b.node.get_our_node_id(), &msg).unwrap();
		resp_2.push(handle_chan_reestablish_msgs!(node_a, node_b));
	}
	if pending_cell_htlc_claims.1 != 0 || pending_cell_htlc_fails.1 != 0 {
		check_added_monitors!(node_a, 1);
	} else {
		check_added_monitors!(node_a, 0);
	}

	// We dont yet support both needing updates, as that would require a different commitment dance:
	assert!((pending_htlc_adds.0 == 0 && pending_htlc_claims.0 == 0 && pending_cell_htlc_claims.0 == 0 && pending_cell_htlc_fails.0 == 0) ||
			(pending_htlc_adds.1 == 0 && pending_htlc_claims.1 == 0 && pending_cell_htlc_claims.1 == 0 && pending_cell_htlc_fails.1 == 0));

	for chan_msgs in resp_1.drain(..) {
		if send_funding_locked.0 {
			node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &chan_msgs.0.unwrap()).unwrap();
			let announcement_event = node_a.node.get_and_clear_pending_msg_events();
			if !announcement_event.is_empty() {
				assert_eq!(announcement_event.len(), 1);
				if let MessageSendEvent::SendAnnouncementSignatures { .. } = announcement_event[0] {
					//TODO: Test announcement_sigs re-sending
				} else { panic!("Unexpected event!"); }
			}
		} else {
			assert!(chan_msgs.0.is_none());
		}
		if pending_raa.0 {
			assert!(chan_msgs.3 == RAACommitmentOrder::RevokeAndACKFirst);
			node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &chan_msgs.1.unwrap()).unwrap();
			assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors!(node_a, 1);
		} else {
			assert!(chan_msgs.1.is_none());
		}
		if pending_htlc_adds.0 != 0 || pending_htlc_claims.0 != 0 || pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
			let commitment_update = chan_msgs.2.unwrap();
			if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
				assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.0 as usize);
			} else {
				assert!(commitment_update.update_add_htlcs.is_empty());
			}
			assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.0 + pending_cell_htlc_claims.0);
			assert_eq!(commitment_update.update_fail_htlcs.len(), pending_cell_htlc_fails.0);
			assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
			for update_add in commitment_update.update_add_htlcs {
				node_a.node.handle_update_add_htlc(&node_b.node.get_our_node_id(), &update_add).unwrap();
			}
			for update_fulfill in commitment_update.update_fulfill_htlcs {
				node_a.node.handle_update_fulfill_htlc(&node_b.node.get_our_node_id(), &update_fulfill).unwrap();
			}
			for update_fail in commitment_update.update_fail_htlcs {
				node_a.node.handle_update_fail_htlc(&node_b.node.get_our_node_id(), &update_fail).unwrap();
			}

			if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
				commitment_signed_dance!(node_a, node_b, commitment_update.commitment_signed, false);
			} else {
				node_a.node.handle_commitment_signed(&node_b.node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
				check_added_monitors!(node_a, 1);
				let as_revoke_and_ack = get_event_msg!(node_a, MessageSendEvent::SendRevokeAndACK, node_b.node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &as_revoke_and_ack).unwrap();
				assert!(node_b.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_b, 1);
			}
		} else {
			assert!(chan_msgs.2.is_none());
		}
	}

	for chan_msgs in resp_2.drain(..) {
		if send_funding_locked.1 {
			node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &chan_msgs.0.unwrap()).unwrap();
			let announcement_event = node_b.node.get_and_clear_pending_msg_events();
			if !announcement_event.is_empty() {
				assert_eq!(announcement_event.len(), 1);
				if let MessageSendEvent::SendAnnouncementSignatures { .. } = announcement_event[0] {
					//TODO: Test announcement_sigs re-sending
				} else { panic!("Unexpected event!"); }
			}
		} else {
			assert!(chan_msgs.0.is_none());
		}
		if pending_raa.1 {
			assert!(chan_msgs.3 == RAACommitmentOrder::RevokeAndACKFirst);
			node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &chan_msgs.1.unwrap()).unwrap();
			assert!(node_b.node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors!(node_b, 1);
		} else {
			assert!(chan_msgs.1.is_none());
		}
		if pending_htlc_adds.1 != 0 || pending_htlc_claims.1 != 0 || pending_cell_htlc_claims.1 != 0 || pending_cell_htlc_fails.1 != 0 {
			let commitment_update = chan_msgs.2.unwrap();
			if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
				assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.1 as usize);
			}
			assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.0 + pending_cell_htlc_claims.0);
			assert_eq!(commitment_update.update_fail_htlcs.len(), pending_cell_htlc_fails.0);
			assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
			for update_add in commitment_update.update_add_htlcs {
				node_b.node.handle_update_add_htlc(&node_a.node.get_our_node_id(), &update_add).unwrap();
			}
			for update_fulfill in commitment_update.update_fulfill_htlcs {
				node_b.node.handle_update_fulfill_htlc(&node_a.node.get_our_node_id(), &update_fulfill).unwrap();
			}
			for update_fail in commitment_update.update_fail_htlcs {
				node_b.node.handle_update_fail_htlc(&node_a.node.get_our_node_id(), &update_fail).unwrap();
			}

			if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
				commitment_signed_dance!(node_b, node_a, commitment_update.commitment_signed, false);
			} else {
				node_b.node.handle_commitment_signed(&node_a.node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
				check_added_monitors!(node_b, 1);
				let bs_revoke_and_ack = get_event_msg!(node_b, MessageSendEvent::SendRevokeAndACK, node_a.node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
				assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_a, 1);
			}
		} else {
			assert!(chan_msgs.2.is_none());
		}
	}
}

#[test]
fn test_simple_peer_disconnect() {
	// Test that we can reconnect when there are no lost messages
	let nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

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
	let mut nodes = create_network(2);
	if messages_delivered == 0 {
		create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001);
		// nodes[1] doesn't receive the funding_locked message (it'll be re-sent on reconnect)
	} else {
		create_announced_chan_between_nodes(&nodes, 0, 1);
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

	nodes[1].node.channel_state.lock().unwrap().next_forward = Instant::now();
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
	let nodes = create_network(2);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

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
fn test_simple_monitor_permanent_update_fail() {
	// Test that we handle a simple permanent monitor update failure
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
	if let Err(APIError::ChannelUnavailable {..}) = nodes[0].node.send_payment(route, payment_hash_1) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 2);
	match events_1[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	};
	match events_1[1] {
		MessageSendEvent::HandleError { node_id, .. } => assert_eq!(node_id, nodes[1].node.get_our_node_id()),
		_ => panic!("Unexpected event"),
	};

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
}

fn do_test_simple_monitor_temporary_update_fail(disconnect: bool) {
	// Test that we can recover from a simple temporary monitor update failure optionally with
	// a disconnect in between
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_1) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	let mut events_2 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let payment_event = SendEvent::from_event(events_2.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_3 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	// Now set it to failed again...
	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route, payment_hash_2) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	// ...and make sure we can force-close a TemporaryFailure channel with a PermanentFailure
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0]);

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
}

#[test]
fn test_simple_monitor_temporary_update_fail() {
	do_test_simple_monitor_temporary_update_fail(false);
	do_test_simple_monitor_temporary_update_fail(true);
}

fn do_test_monitor_temporary_update_fail(disconnect_count: usize) {
	let disconnect_flags = 8 | 16;

	// Test that we can recover from a temporary monitor update failure with some in-flight
	// HTLCs going on at the same time potentially with some disconnection thrown in.
	// * First we route a payment, then get a temporary monitor update failure when trying to
	//   route a second payment. We then claim the first payment.
	// * If disconnect_count is set, we will disconnect at this point (which is likely as
	//   TemporaryFailure likely indicates net disconnect which resulted in failing to update
	//   the ChannelMonitor on a watchtower).
	// * If !(disconnect_count & 16) we deliver a update_fulfill_htlc/CS for the first payment
	//   immediately, otherwise we wait sconnect and deliver them via the reconnect
	//   channel_reestablish processing (ie disconnect_count & 16 makes no sense if
	//   disconnect_count & !disconnect_flags is 0).
	// * We then update the channel monitor, reconnecting if disconnect_count is set and walk
	//   through message sending, potentially disconnect/reconnecting multiple times based on
	//   disconnect_count, to get the update_fulfill_htlc through.
	// * We then walk through more message exchanges to get the original update_add_htlc
	//   through, swapping message ordering based on disconnect_count & 8 and optionally
	//   disconnect/reconnecting based on disconnect_count.
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_2) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Claim the previous payment, which will result in a update_fulfill_htlc/CS from nodes[1]
	// but nodes[0] won't respond since it is frozen.
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let (bs_initial_fulfill, bs_initial_commitment_signed) = match events_2[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			if (disconnect_count & 16) == 0 {
				nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]).unwrap();
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
					},
					_ => panic!("Unexpected event"),
				}

				if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::IgnoreError) }) = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed) {
					assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
				} else { panic!(); }
			}

			(update_fulfill_htlcs[0].clone(), commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if disconnect_count & !disconnect_flags > 0 {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	}

	// Now fix monitor updating...
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	macro_rules! disconnect_reconnect_peers { () => { {
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

		(reestablish_1, reestablish_2, as_resp, bs_resp)
	} } }

	let (payment_event, initial_revoke_and_ack) = if disconnect_count & !disconnect_flags > 0 {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
		check_added_monitors!(nodes[0], 0);
		let mut as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
		check_added_monitors!(nodes[1], 0);
		let mut bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		assert!(bs_resp.1.is_none());
		if (disconnect_count & 16) == 0 {
			assert!(bs_resp.2.is_none());

			assert!(as_resp.1.is_some());
			assert!(as_resp.2.is_some());
			assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);
		} else {
			assert!(bs_resp.2.as_ref().unwrap().update_add_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fee.is_none());
			assert!(bs_resp.2.as_ref().unwrap().update_fulfill_htlcs == vec![bs_initial_fulfill]);
			assert!(bs_resp.2.as_ref().unwrap().commitment_signed == bs_initial_commitment_signed);

			assert!(as_resp.1.is_none());

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().update_fulfill_htlcs[0]).unwrap();
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().commitment_signed).unwrap();
			let as_resp_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);

			as_resp.1 = Some(as_resp_raa);
			bs_resp.2 = None;
		}

		if disconnect_count & !disconnect_flags > 1 {
			let (second_reestablish_1, second_reestablish_2, second_as_resp, second_bs_resp) = disconnect_reconnect_peers!();

			if (disconnect_count & 16) == 0 {
				assert!(reestablish_1 == second_reestablish_1);
				assert!(reestablish_2 == second_reestablish_2);
			}
			assert!(as_resp == second_as_resp);
			assert!(bs_resp == second_bs_resp);
		}

		(SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), as_resp.2.unwrap()), as_resp.1.unwrap())
	} else {
		let mut events_4 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_4.len(), 2);
		(SendEvent::from_event(events_4.remove(0)), match events_4[0] {
			MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		})
	};

	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// nodes[1] is awaiting an RAA from nodes[0] still so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	if disconnect_count & !disconnect_flags > 2 {
		let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

		assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
		assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

		assert!(as_resp.2.is_none());
		assert!(bs_resp.2.is_none());
	}

	let as_commitment_update;
	let bs_second_commitment_update;

	macro_rules! handle_bs_raa { () => {
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		as_commitment_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(as_commitment_update.update_add_htlcs.is_empty());
		assert!(as_commitment_update.update_fulfill_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(as_commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[0], 1);
	} }

	macro_rules! handle_initial_raa { () => {
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &initial_revoke_and_ack).unwrap();
		bs_second_commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(bs_second_commitment_update.update_add_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fulfill_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fail_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[1], 1);
	} }

	if (disconnect_count & 8) == 0 {
		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.is_none());

			assert!(as_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
		}
	} else {
		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

			assert!(as_resp.2.is_none());
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);

			assert!(bs_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
		}
	}

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_update.commitment_signed).unwrap();
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_update.commitment_signed).unwrap();
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_monitor_temporary_update_fail_a() {
	do_test_monitor_temporary_update_fail(0);
	do_test_monitor_temporary_update_fail(1);
	do_test_monitor_temporary_update_fail(2);
	do_test_monitor_temporary_update_fail(3);
	do_test_monitor_temporary_update_fail(4);
	do_test_monitor_temporary_update_fail(5);
}

#[test]
fn test_monitor_temporary_update_fail_b() {
	do_test_monitor_temporary_update_fail(2 | 8);
	do_test_monitor_temporary_update_fail(3 | 8);
	do_test_monitor_temporary_update_fail(4 | 8);
	do_test_monitor_temporary_update_fail(5 | 8);
}

#[test]
fn test_monitor_temporary_update_fail_c() {
	do_test_monitor_temporary_update_fail(1 | 16);
	do_test_monitor_temporary_update_fail(2 | 16);
	do_test_monitor_temporary_update_fail(3 | 16);
	do_test_monitor_temporary_update_fail(2 | 8 | 16);
	do_test_monitor_temporary_update_fail(3 | 8 | 16);
}

#[test]
fn test_monitor_update_fail_cs() {
	// Tests handling of a monitor update failure when processing an incoming commitment_signed
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event.commitment_msg).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);
	let responses = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(responses.len(), 2);

	match responses[0] {
		MessageSendEvent::SendRevokeAndACK { ref msg, ref node_id } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &msg).unwrap();
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}
	match responses[1] {
		MessageSendEvent::UpdateHTLCs { ref updates, ref node_id } => {
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());

			*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
			if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed).unwrap_err() {
				assert_eq!(err, "Failed to update ChannelMonitor");
			} else { panic!(); }
			check_added_monitors!(nodes[0], 1);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		},
		_ => panic!("Unexpected event"),
	}

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	let final_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &final_raa).unwrap();
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { payment_hash, amt } => {
			assert_eq!(payment_hash, our_payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
}

fn do_test_monitor_update_fail_raa(test_ignore_second_cs: bool) {
	// Tests handling of a monitor update failure when processing an incoming RAA
	let mut nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance a bit so that we can send backwards from 2 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	// Route a first payment that we'll fail backwards
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Fail the payment backwards, failing the monitor update on nodes[1]'s receipt of the RAA
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1, 0));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();

	let bs_revoke_and_ack = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	check_added_monitors!(nodes[0], 0);

	// While the second channel is AwaitingRAA, forward a second payment to get it into the
	// holding cell.
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	nodes[0].node.send_payment(route, payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now fail monitor updating.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Attempt to forward a third payment but fail due to the second channel being unavailable
	// for forwarding.

	let (_, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	nodes[0].node.send_payment(route, payment_hash_3).unwrap();
	check_added_monitors!(nodes[0], 1);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(()); // We succeed in updating the monitor for the first channel
	send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true);
	check_added_monitors!(nodes[1], 0);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2.remove(0) {
		MessageSendEvent::UpdateHTLCs { node_id, updates } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fee.is_none());

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
			commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false, true);

			let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(msg_events.len(), 1);
			match msg_events[0] {
				MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
					assert_eq!(msg.contents.short_channel_id, chan_2.0.contents.short_channel_id);
					assert_eq!(msg.contents.flags & 2, 2); // temp disabled
				},
				_ => panic!("Unexpected event"),
			}

			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events[0] {
				assert_eq!(payment_hash, payment_hash_3);
				assert!(!rejected_by_dest);
			} else { panic!("Unexpected event!"); }
		},
		_ => panic!("Unexpected event type!"),
	};

	let (payment_preimage_4, payment_hash_4) = if test_ignore_second_cs {
		// Try to route another payment backwards from 2 to make sure 1 holds off on responding
		let (payment_preimage_4, payment_hash_4) = get_payment_preimage_hash!(nodes[0]);
		let route = nodes[2].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		nodes[2].node.send_payment(route, payment_hash_4).unwrap();
		check_added_monitors!(nodes[2], 1);

		send_event = SendEvent::from_event(nodes[2].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
		if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::IgnoreError) }) = nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &send_event.commitment_msg) {
			assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
		} else { panic!(); }
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		(Some(payment_preimage_4), Some(payment_hash_4))
	} else { (None, None) };

	// Restore monitor updating, ensuring we immediately get a fail-back update and a
	// update_add update.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let mut events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	if test_ignore_second_cs {
		assert_eq!(events_3.len(), 3);
	} else {
		assert_eq!(events_3.len(), 2);
	}

	// Note that the ordering of the events for different nodes is non-prescriptive, though the
	// ordering of the two events that both go to nodes[2] have to stay in the same order.
	let messages_a = match events_3.pop().unwrap() {
		MessageSendEvent::UpdateHTLCs { node_id, mut updates } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fail_htlcs.remove(0), updates.commitment_signed)
		},
		_ => panic!("Unexpected event type!"),
	};
	let raa = if test_ignore_second_cs {
		match events_3.remove(1) {
			MessageSendEvent::SendRevokeAndACK { node_id, msg } => {
				assert_eq!(node_id, nodes[2].node.get_our_node_id());
				Some(msg.clone())
			},
			_ => panic!("Unexpected event"),
		}
	} else { None };
	let send_event_b = SendEvent::from_event(events_3.remove(0));
	assert_eq!(send_event_b.node_id, nodes[2].node.get_our_node_id());

	// Now deliver the new messages...

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &messages_a.0).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], messages_a.1, false);
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events_4[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(rejected_by_dest);
	} else { panic!("Unexpected event!"); }

	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_b.msgs[0]).unwrap();
	if test_ignore_second_cs {
		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_b.commitment_msg).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_revoke_and_ack = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa.unwrap()).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_cs = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert!(bs_cs.update_add_htlcs.is_empty());
		assert!(bs_cs.update_fail_htlcs.is_empty());
		assert!(bs_cs.update_fail_malformed_htlcs.is_empty());
		assert!(bs_cs.update_fulfill_htlcs.is_empty());
		assert!(bs_cs.update_fee.is_none());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		check_added_monitors!(nodes[1], 1);
		let as_cs = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
		assert!(as_cs.update_add_htlcs.is_empty());
		assert!(as_cs.update_fail_htlcs.is_empty());
		assert!(as_cs.update_fail_malformed_htlcs.is_empty());
		assert!(as_cs.update_fulfill_htlcs.is_empty());
		assert!(as_cs.update_fee.is_none());

		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_cs.commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_cs.commitment_signed).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_second_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa).unwrap();
		check_added_monitors!(nodes[2], 1);
		assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_second_raa).unwrap();
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	} else {
		commitment_signed_dance!(nodes[2], nodes[1], send_event_b.commitment_msg, false);
	}

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events_6 = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events_6.len(), 1);
	match events_6[0] {
		Event::PaymentReceived { payment_hash, .. } => { assert_eq!(payment_hash, payment_hash_2); },
		_ => panic!("Unexpected event"),
	};

	if test_ignore_second_cs {
		expect_pending_htlcs_forwardable!(nodes[1]);
		check_added_monitors!(nodes[1], 1);

		send_event = SendEvent::from_node(&nodes[1]);
		assert_eq!(send_event.node_id, nodes[0].node.get_our_node_id());
		assert_eq!(send_event.msgs.len(), 1);
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
		commitment_signed_dance!(nodes[0], nodes[1], send_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[0]);

		let events_9 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_9.len(), 1);
		match events_9[0] {
			Event::PaymentReceived { payment_hash, .. } => assert_eq!(payment_hash, payment_hash_4.unwrap()),
			_ => panic!("Unexpected event"),
		};
		claim_payment(&nodes[2], &[&nodes[1], &nodes[0]], payment_preimage_4.unwrap());
	}

	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_2);
}

#[test]
fn test_monitor_update_fail_raa() {
	do_test_monitor_update_fail_raa(false);
	do_test_monitor_update_fail_raa(true);
}

#[test]
fn test_monitor_update_fail_reestablish() {
	// Simple test for message retransmission after monitor update failure on
	// channel_reestablish generating a monitor update (which comes from freeing holding cell
	// HTLCs).
	let mut nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish).unwrap();

	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	assert!(as_reestablish == get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id()));
	assert!(bs_reestablish == get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()));

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish).unwrap();

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish).unwrap();
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);

	updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { payment_preimage, .. } => assert_eq!(payment_preimage, our_payment_preimage),
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_invalid_channel_announcement() {
	//Test BOLT 7 channel_announcement msg requirement for final node, gather data to build customed channel_announcement msgs
	let secp_ctx = Secp256k1::new();
	let nodes = create_network(2);

	let chan_announcement = create_chan_between_nodes(&nodes[0], &nodes[1]);

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
			let msghash = Message::from_slice(&Sha256dHash::from_data(&$unsigned_msg.encode()[..])[..]).unwrap();
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
	unsigned_msg.chain_hash = Sha256dHash::from_data(&[1,2,3,4,5,6,7,8,9]);
	sign_msg!(unsigned_msg);
	assert!(nodes[0].router.handle_channel_announcement(&chan_announcement).is_err());
}

struct VecWriter(Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}

#[test]
fn test_no_txn_manager_serialize_deserialize() {
	let mut nodes = create_network(2);

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = VecWriter(Vec::new());
	nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let config = UserConfig::new();
	let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
	let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = VecWriter(Vec::new());
	nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
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
	// Test deserializing a ChannelManager with a out-of-date ChannelMonitor
	let mut nodes = create_network(4);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 2, 0);
	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 3);

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
		let mut writer = VecWriter(Vec::new());
		monitor.1.write_for_disk(&mut writer).unwrap();
		node_0_monitors_serialized.push(writer.0);
	}

	nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
	let mut node_0_monitors = Vec::new();
	for serialized in node_0_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut read, Arc::new(test_utils::TestLogger::new())).unwrap();
		assert!(read.is_empty());
		node_0_monitors.push(monitor);
	}

	let mut nodes_0_read = &nodes_0_serialized[..];
	let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
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
										script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
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
									let witness_script = Address::p2pkh(&remotepubkey, Network::Testnet).script_pubkey();
									let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], &witness_script, output.value)[..]).unwrap();
									let remotesig = secp_ctx.sign(&sighash, key);
									spend_tx.input[0].witness.push(remotesig.serialize_der(&secp_ctx).to_vec());
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
										script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
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
									spend_tx.input[0].witness.push(local_delaysig.serialize_der(&secp_ctx).to_vec());
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
										script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
										value: output.value,
									};
									let mut spend_tx = Transaction {
										version: 2,
										lock_time: 0,
										input: vec![input],
										output: vec![outp.clone()],
									};
									let secret = {
										match ExtendedPrivKey::new_master(&secp_ctx, Network::Testnet, &$node.node_seed) {
											Ok(master_key) => {
												match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx($der_idx)) {
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
									let sig = secp_ctx.sign(&sighash, &secret.secret_key);
									spend_tx.input[0].witness.push(sig.serialize_der(&secp_ctx).to_vec());
									spend_tx.input[0].witness[0].push(SigHashType::All as u8);
									spend_tx.input[0].witness.push(pubkey.serialize().to_vec());
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
	let nodes = create_network(2);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000);
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

	let nodes = create_network(2);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000);
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

	let nodes = create_network(2);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000);
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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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

	let nodes = create_network(3);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

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
	let mut nodes = create_network(3);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(6);

	create_announced_chan_between_nodes(&nodes, 0, 2);
	create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan = create_announced_chan_between_nodes(&nodes, 2, 3);
	create_announced_chan_between_nodes(&nodes, 3, 4);
	create_announced_chan_between_nodes(&nodes, 3, 5);

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
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_1, ds_dust_limit*1000));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_3, 1000000));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_5, 1000000));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_6, ds_dust_limit*1000));
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
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_2, ds_dust_limit*1000));
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_4, 1000000));
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
	let nodes = create_network(2);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

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
	let nodes = create_network(2);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

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

fn run_onion_failure_test<F1,F2>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, callback_msg: F1, callback_node: F2, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: FnMut(),
{
	run_onion_failure_test_with_fail_intercept(_name, test_case, nodes, route, payment_hash, callback_msg, |_|{}, callback_node, expected_retryable, expected_error_code, expected_channel_update);
}

// test_case
// 0: node1 fail backward
// 1: final node fail backward
// 2: payment completed but the user reject the payment
// 3: final node fail backward (but tamper onion payloads from node0)
// 100: trigger error in the intermediate node and tamper returnning fail_htlc
// 200: trigger error in the final node and tamper returnning fail_htlc
fn run_onion_failure_test_with_fail_intercept<F1,F2,F3>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, mut callback_msg: F1, mut callback_fail: F2, mut callback_node: F3, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: for <'a> FnMut(&'a mut msgs::UpdateFailHTLC),
				F3: FnMut(),
{
	use ln::msgs::HTLCFailChannelUpdate;

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
			$node.node.channel_state.lock().unwrap().next_forward = Instant::now();
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
				chain_hash: Sha256dHash::from_data(&vec![0u8][..]),
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

	let mut nodes = create_network(3);
	for node in nodes.iter() {
		*node.keys_manager.override_session_priv.lock().unwrap() = Some(SecretKey::from_slice(&Secp256k1::without_caps(), &[3; 32]).unwrap());
	}
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1), create_announced_chan_between_nodes(&nodes, 1, 2)];
	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap();
	// positve case
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 40000);

	// intermediate node failure
	run_onion_failure_test("invalid_realm", 0, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height).unwrap();
		onion_payloads[0].realm = 3;
		msg.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);
	}, ||{}, true, Some(PERM|1), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));//XXX incremented channels idx here

	// final node failure
	run_onion_failure_test("invalid_realm", 3, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
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
		// and tamper returing error message
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], NODE|2, &[0;0]);
	}, ||{}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: false}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		// and tamper returing error message
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
	}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[1].pubkey, is_permanent: false}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{}, true, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
	}, false, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[1].pubkey, is_permanent: true}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
	}, true, Some(PERM|NODE|3), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.hops[0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
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
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], UPDATE|7, &ChannelUpdate::dummy().encode_with_len()[..]);
	}, ||{}, true, Some(UPDATE|7), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test_with_fail_intercept("permanent_channel_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route, &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|8, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|8), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test_with_fail_intercept("required_channel_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
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
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - HTLC_FAIL_TIMEOUT_BLOCKS + 1;
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_checked(&header, height, &Vec::new()[..], &[0; 0]);
	}, ||{}, true, Some(UPDATE|14), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test("unknown_payment_hash", 2, &nodes, &route, &payment_hash, |_| {}, || {
		nodes[2].node.fail_htlc_backwards(&payment_hash, 0);
	}, false, Some(PERM|15), None);

	run_onion_failure_test("final_expiry_too_soon", 1, &nodes, &route, &payment_hash, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - HTLC_FAIL_TIMEOUT_BLOCKS + 1;
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
		let session_priv = SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[3; 32]).unwrap();
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
