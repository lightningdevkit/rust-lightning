//! A bunch of useful utilities for building networks of nodes and exchanging messages between
//! nodes for functional tests.

use chain::chaininterface;
use chain::transaction::OutPoint;
use chain::keysinterface::KeysInterface;
use ln::channelmanager::{ChannelManager,RAACommitmentOrder, PaymentPreimage, PaymentHash};
use ln::router::{Route, Router};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler, LocalFeatures};
use util::test_utils;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::logger::Logger;
use util::config::UserConfig;

use bitcoin::util::hash::BitcoinHash;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::network::constants::Network;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256d::Hash as Sha256d;
use bitcoin_hashes::Hash;

use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;

use rand::{thread_rng,Rng};

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::mem;

pub const CHAN_CONFIRM_DEPTH: u32 = 100;
pub fn confirm_transaction(chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction, chan_id: u32) {
	assert!(chain.does_match_tx(tx));
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain.block_connected_checked(&header, 1, &[tx; 1], &[chan_id; 1]);
	for i in 2..CHAN_CONFIRM_DEPTH {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		chain.block_connected_checked(&header, i, &[tx; 0], &[0; 0]);
	}
}

pub fn connect_blocks(chain: &chaininterface::ChainWatchInterfaceUtil, depth: u32, height: u32, parent: bool, prev_blockhash: Sha256d) -> Sha256d {
	let mut header = BlockHeader { version: 0x2000000, prev_blockhash: if parent { prev_blockhash } else { Default::default() }, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain.block_connected_checked(&header, height + 1, &Vec::new(), &Vec::new());
	for i in 2..depth + 1 {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		chain.block_connected_checked(&header, height + i, &Vec::new(), &Vec::new());
	}
	header.bitcoin_hash()
}

pub struct Node {
	pub chain_monitor: Arc<chaininterface::ChainWatchInterfaceUtil>,
	pub tx_broadcaster: Arc<test_utils::TestBroadcaster>,
	pub chan_monitor: Arc<test_utils::TestChannelMonitor>,
	pub keys_manager: Arc<test_utils::TestKeysInterface>,
	pub node: Arc<ChannelManager>,
	pub router: Router,
	pub node_seed: [u8; 32],
	pub network_payment_count: Rc<RefCell<u8>>,
	pub network_chan_count: Rc<RefCell<u32>>,
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

pub fn create_chan_between_nodes(node_a: &Node, node_b: &Node, a_flags: LocalFeatures, b_flags: LocalFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001, a_flags, b_flags)
}

pub fn create_chan_between_nodes_with_value(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64, a_flags: LocalFeatures, b_flags: LocalFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
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

pub fn create_funding_transaction(node: &Node, expected_chan_value: u64, expected_user_chan_id: u64) -> ([u8; 32], Transaction, OutPoint) {
	let chan_id = *node.network_chan_count.borrow();

	let events = node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(*channel_value_satoshis, expected_chan_value);
			assert_eq!(user_channel_id, expected_user_chan_id);

			let tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
				value: *channel_value_satoshis, script_pubkey: output_script.clone(),
			}]};
			let funding_outpoint = OutPoint::new(tx.txid(), 0);
			(*temporary_channel_id, tx, funding_outpoint)
		},
		_ => panic!("Unexpected event"),
	}
}

pub fn create_chan_between_nodes_with_value_init(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64, a_flags: LocalFeatures, b_flags: LocalFeatures) -> Transaction {
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42).unwrap();
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), a_flags, &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id())).unwrap();
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), b_flags, &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id())).unwrap();

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(node_a, channel_value, 42);

	{
		node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
		let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
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

pub fn create_chan_between_nodes_with_value_confirm_first(node_recv: &Node, node_conf: &Node, tx: &Transaction) {
	confirm_transaction(&node_conf.chain_monitor, &tx, tx.version);
	node_recv.node.handle_funding_locked(&node_conf.node.get_our_node_id(), &get_event_msg!(node_conf, MessageSendEvent::SendFundingLocked, node_recv.node.get_our_node_id())).unwrap();
}

pub fn create_chan_between_nodes_with_value_confirm_second(node_recv: &Node, node_conf: &Node) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	let channel_id;
	let events_6 = node_conf.node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 2);
	((match events_6[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
			channel_id = msg.channel_id.clone();
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}, match events_6[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}), channel_id)
}

pub fn create_chan_between_nodes_with_value_confirm(node_a: &Node, node_b: &Node, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	create_chan_between_nodes_with_value_confirm_first(node_a, node_b, tx);
	confirm_transaction(&node_a.chain_monitor, &tx, tx.version);
	create_chan_between_nodes_with_value_confirm_second(node_b, node_a)
}

pub fn create_chan_between_nodes_with_value_a(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64, a_flags: LocalFeatures, b_flags: LocalFeatures) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b(node_a: &Node, node_b: &Node, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
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

pub fn create_announced_chan_between_nodes(nodes: &Vec<Node>, a: usize, b: usize, a_flags: LocalFeatures, b_flags: LocalFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001, a_flags, b_flags)
}

pub fn create_announced_chan_between_nodes_with_value(nodes: &Vec<Node>, a: usize, b: usize, channel_value: u64, push_msat: u64, a_flags: LocalFeatures, b_flags: LocalFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat, a_flags, b_flags);
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
			$tx.verify(|out_point| {
				if out_point.txid == $spends_tx.txid() {
					$spends_tx.output.get(out_point.vout as usize).cloned()
				} else {
					None
				}
			}).unwrap();
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

pub fn close_channel(outbound_node: &Node, inbound_node: &Node, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
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

pub struct SendEvent {
	pub node_id: PublicKey,
	pub msgs: Vec<msgs::UpdateAddHTLC>,
	pub commitment_msg: msgs::CommitmentSigned,
}
impl SendEvent {
	pub fn from_commitment_update(node_id: PublicKey, updates: msgs::CommitmentUpdate) -> SendEvent {
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		SendEvent { node_id: node_id, msgs: updates.update_add_htlcs, commitment_msg: updates.commitment_signed }
	}

	pub fn from_event(event: MessageSendEvent) -> SendEvent {
		match event {
			MessageSendEvent::UpdateHTLCs { node_id, updates } => SendEvent::from_commitment_update(node_id, updates),
			_ => panic!("Unexpected event type!"),
		}
	}

	pub fn from_node(node: &Node) -> SendEvent {
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
		$node.node.process_pending_htlc_forwards();
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
}

macro_rules! expect_payment_sent {
	($node: expr, $expected_payment_preimage: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!($expected_payment_preimage, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

pub fn send_along_route_with_hash(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64, our_payment_hash: PaymentHash) {
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

pub fn send_along_route(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	send_along_route_with_hash(origin_node, route, expected_route, recv_value, our_payment_hash);
	(our_payment_preimage, our_payment_hash)
}

pub fn claim_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_preimage: PaymentPreimage) {
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
		expect_payment_sent!(origin_node, our_payment_preimage);
	}
}

pub fn claim_payment(origin_node: &Node, expected_route: &[&Node], our_payment_preimage: PaymentPreimage) {
	claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage);
}

pub const TEST_FINAL_CLTV: u32 = 32;

pub fn route_payment(origin_node: &Node, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.hops.len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	send_along_route(origin_node, route, expected_route, recv_value)
}

pub fn route_over_limit(origin_node: &Node, expected_route: &[&Node], recv_value: u64) {
	let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.hops.len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	let (_, our_payment_hash) = get_payment_preimage_hash!(origin_node);

	let err = origin_node.node.send_payment(route, our_payment_hash).err().unwrap();
	match err {
		APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over the max HTLC value in flight our peer will accept"),
		_ => panic!("Unknown error variants"),
	};
}

pub fn send_payment(origin: &Node, expected_route: &[&Node], recv_value: u64) {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage);
}

pub fn fail_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_hash: PaymentHash) {
	assert!(expected_route.last().unwrap().node.fail_htlc_backwards(&our_payment_hash));
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

pub fn fail_payment(origin_node: &Node, expected_route: &[&Node], our_payment_hash: PaymentHash) {
	fail_payment_along_route(origin_node, expected_route, false, our_payment_hash);
}

pub fn create_network(node_count: usize, node_config: &[Option<UserConfig>]) -> Vec<Node> {
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
		let chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone(), logger.clone(), feeest.clone()));
		let mut default_config = UserConfig::new();
		default_config.channel_options.announced_channel = true;
		default_config.peer_channel_config_limits.force_announced_channel_preference = false;
		let node = ChannelManager::new(Network::Testnet, feeest.clone(), chan_monitor.clone(), chain_monitor.clone(), tx_broadcaster.clone(), Arc::clone(&logger), keys_manager.clone(), if node_config[i].is_some() { node_config[i].clone().unwrap() } else { default_config }).unwrap();
		let router = Router::new(PublicKey::from_secret_key(&secp_ctx, &keys_manager.get_node_secret()), chain_monitor.clone(), Arc::clone(&logger));
		nodes.push(Node { chain_monitor, tx_broadcaster, chan_monitor, node, router, keys_manager, node_seed: seed,
			network_payment_count: payment_count.clone(),
			network_chan_count: chan_count.clone(),
		});
	}

	nodes
}

#[derive(PartialEq)]
pub enum HTLCType { NONE, TIMEOUT, SUCCESS }
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
pub fn test_txn_broadcast(node: &Node, chan: &(msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction), commitment_tx: Option<Transaction>, has_htlc_tx: HTLCType) -> Vec<Transaction> {
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
pub fn test_revoked_htlc_claim_txn_broadcast(node: &Node, revoked_tx: Transaction) {
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

pub fn check_preimage_claim(node: &Node, prev_txn: &Vec<Transaction>) -> Vec<Transaction> {
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

pub fn get_announce_close_broadcast_events(nodes: &Vec<Node>, a: usize, b: usize) {
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

macro_rules! get_channel_value_stat {
	($node: expr, $channel_id: expr) => {{
		let chan_lock = $node.node.channel_state.lock().unwrap();
		let chan = chan_lock.by_id.get(&$channel_id).unwrap();
		chan.get_value_stat()
	}}
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
pub fn reconnect_nodes(node_a: &Node, node_b: &Node, send_funding_locked: (bool, bool), pending_htlc_adds: (i64, i64), pending_htlc_claims: (usize, usize), pending_cell_htlc_claims: (usize, usize), pending_cell_htlc_fails: (usize, usize), pending_raa: (bool, bool)) {
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

	// We don't yet support both needing updates, as that would require a different commitment dance:
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
