// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A bunch of useful utilities for building networks of nodes and exchanging messages between
//! nodes for functional tests.

use chain::Watch;
use chain::channelmonitor::ChannelMonitor;
use chain::transaction::OutPoint;
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, RAACommitmentOrder, PaymentPreimage, PaymentHash, PaymentSecret, PaymentSendFailure};
use routing::router::{Route, get_route};
use routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler};
use util::enforcing_trait_impls::EnforcingSigner;
use util::test_utils;
use util::test_utils::TestChainMonitor;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::config::UserConfig;
use util::ser::{ReadableArgs, Writeable, Readable};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::network::constants::Network;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::hash_types::BlockHash;

use bitcoin::secp256k1::key::PublicKey;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;
use std::mem;
use std::collections::HashMap;

pub const CHAN_CONFIRM_DEPTH: u32 = 100;

pub fn confirm_transaction<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
	let dummy_tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: Vec::new() };
	let dummy_tx_count = tx.version as usize;
	let mut block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![dummy_tx; dummy_tx_count],
	};
	block.txdata.push(tx.clone());
	connect_block(node, &block, 1);
	for i in 2..CHAN_CONFIRM_DEPTH {
		block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: block.header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(node, &block, i);
	}
}

pub fn connect_blocks<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, depth: u32, height: u32, parent: bool, prev_blockhash: BlockHash) -> BlockHash {
	let mut block = Block {
		header: BlockHeader { version: 0x2000000, prev_blockhash: if parent { prev_blockhash } else { Default::default() }, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	connect_block(node, &block, height + 1);
	for i in 2..depth + 1 {
		block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: block.header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(node, &block, height + i);
	}
	block.header.block_hash()
}

pub fn connect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, block: &Block, height: u32) {
	let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
	node.chain_monitor.chain_monitor.block_connected(&block.header, &txdata, height);
	node.node.block_connected(&block.header, &txdata, height);
}

pub fn disconnect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, header: &BlockHeader, height: u32) {
	node.chain_monitor.chain_monitor.block_disconnected(header, height);
	node.node.block_disconnected(header);
}

pub struct TestChanMonCfg {
	pub tx_broadcaster: test_utils::TestBroadcaster,
	pub fee_estimator: test_utils::TestFeeEstimator,
	pub chain_source: test_utils::TestChainSource,
	pub persister: test_utils::TestPersister,
	pub logger: test_utils::TestLogger,
	pub keys_manager: test_utils::TestKeysInterface,
}

pub struct NodeCfg<'a> {
	pub chain_source: &'a test_utils::TestChainSource,
	pub tx_broadcaster: &'a test_utils::TestBroadcaster,
	pub fee_estimator: &'a test_utils::TestFeeEstimator,
	pub chain_monitor: test_utils::TestChainMonitor<'a>,
	pub keys_manager: &'a test_utils::TestKeysInterface,
	pub logger: &'a test_utils::TestLogger,
	pub node_seed: [u8; 32],
}

pub struct Node<'a, 'b: 'a, 'c: 'b> {
	pub chain_source: &'c test_utils::TestChainSource,
	pub tx_broadcaster: &'c test_utils::TestBroadcaster,
	pub chain_monitor: &'b test_utils::TestChainMonitor<'c>,
	pub keys_manager: &'b test_utils::TestKeysInterface,
	pub node: &'a ChannelManager<EnforcingSigner, &'b TestChainMonitor<'c>, &'c test_utils::TestBroadcaster, &'b test_utils::TestKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>,
	pub net_graph_msg_handler: NetGraphMsgHandler<&'c test_utils::TestChainSource, &'c test_utils::TestLogger>,
	pub node_seed: [u8; 32],
	pub network_payment_count: Rc<RefCell<u8>>,
	pub network_chan_count: Rc<RefCell<u32>>,
	pub logger: &'c test_utils::TestLogger,
}

impl<'a, 'b, 'c> Drop for Node<'a, 'b, 'c> {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Check that we processed all pending events
			assert!(self.node.get_and_clear_pending_msg_events().is_empty());
			assert!(self.node.get_and_clear_pending_events().is_empty());
			assert!(self.chain_monitor.added_monitors.lock().unwrap().is_empty());

			// Check that if we serialize the Router, we can deserialize it again.
			{
				let mut w = test_utils::TestVecWriter(Vec::new());
				let network_graph_ser = self.net_graph_msg_handler.network_graph.read().unwrap();
				network_graph_ser.write(&mut w).unwrap();
				let network_graph_deser = <NetworkGraph>::read(&mut ::std::io::Cursor::new(&w.0)).unwrap();
				assert!(network_graph_deser == *self.net_graph_msg_handler.network_graph.read().unwrap());
				let net_graph_msg_handler = NetGraphMsgHandler::from_net_graph(
					Some(self.chain_source), self.logger, network_graph_deser
				);
				let mut chan_progress = 0;
				loop {
					let orig_announcements = self.net_graph_msg_handler.get_next_channel_announcements(chan_progress, 255);
					let deserialized_announcements = net_graph_msg_handler.get_next_channel_announcements(chan_progress, 255);
					assert!(orig_announcements == deserialized_announcements);
					chan_progress = match orig_announcements.last() {
						Some(announcement) => announcement.0.contents.short_channel_id + 1,
						None => break,
					};
				}
				let mut node_progress = None;
				loop {
					let orig_announcements = self.net_graph_msg_handler.get_next_node_announcements(node_progress.as_ref(), 255);
					let deserialized_announcements = net_graph_msg_handler.get_next_node_announcements(node_progress.as_ref(), 255);
					assert!(orig_announcements == deserialized_announcements);
					node_progress = match orig_announcements.last() {
						Some(announcement) => Some(announcement.contents.node_id),
						None => break,
					};
				}
			}

			// Check that if we serialize and then deserialize all our channel monitors we get the
			// same set of outputs to watch for on chain as we have now. Note that if we write
			// tests that fully close channels and remove the monitors at some point this may break.
			let feeest = test_utils::TestFeeEstimator { sat_per_kw: 253 };
			let mut deserialized_monitors = Vec::new();
			{
				let old_monitors = self.chain_monitor.chain_monitor.monitors.read().unwrap();
				for (_, old_monitor) in old_monitors.iter() {
					let mut w = test_utils::TestVecWriter(Vec::new());
					old_monitor.write(&mut w).unwrap();
					let (_, deserialized_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
						&mut ::std::io::Cursor::new(&w.0), self.keys_manager).unwrap();
					deserialized_monitors.push(deserialized_monitor);
				}
			}

			// Before using all the new monitors to check the watch outpoints, use the full set of
			// them to ensure we can write and reload our ChannelManager.
			{
				let mut channel_monitors = HashMap::new();
				for monitor in deserialized_monitors.iter_mut() {
					channel_monitors.insert(monitor.get_funding_txo().0, monitor);
				}

				let mut w = test_utils::TestVecWriter(Vec::new());
				self.node.write(&mut w).unwrap();
				<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut ::std::io::Cursor::new(w.0), ChannelManagerReadArgs {
					default_config: UserConfig::default(),
					keys_manager: self.keys_manager,
					fee_estimator: &test_utils::TestFeeEstimator { sat_per_kw: 253 },
					chain_monitor: self.chain_monitor,
					tx_broadcaster: &test_utils::TestBroadcaster {
						txn_broadcasted: Mutex::new(self.tx_broadcaster.txn_broadcasted.lock().unwrap().clone())
					},
					logger: &test_utils::TestLogger::new(),
					channel_monitors,
				}).unwrap();
			}

			let persister = test_utils::TestPersister::new();
			let broadcaster = test_utils::TestBroadcaster {
				txn_broadcasted: Mutex::new(self.tx_broadcaster.txn_broadcasted.lock().unwrap().clone())
			};
			let chain_source = test_utils::TestChainSource::new(Network::Testnet);
			let chain_monitor = test_utils::TestChainMonitor::new(Some(&chain_source), &broadcaster, &self.logger, &feeest, &persister, &self.keys_manager);
			for deserialized_monitor in deserialized_monitors.drain(..) {
				if let Err(_) = chain_monitor.watch_channel(deserialized_monitor.get_funding_txo().0, deserialized_monitor) {
					panic!();
				}
			}
			assert_eq!(*chain_source.watched_txn.lock().unwrap(), *self.chain_source.watched_txn.lock().unwrap());
			assert_eq!(*chain_source.watched_outputs.lock().unwrap(), *self.chain_source.watched_outputs.lock().unwrap());
		}
	}
}

pub fn create_chan_between_nodes<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001, a_flags, b_flags)
}

pub fn create_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
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

/// Get an specific event message from the pending events queue.
#[macro_export]
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

#[cfg(test)]
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

#[cfg(test)]
macro_rules! get_feerate {
	($node: expr, $channel_id: expr) => {
		{
			let chan_lock = $node.node.channel_state.lock().unwrap();
			let chan = chan_lock.by_id.get(&$channel_id).unwrap();
			chan.get_feerate()
		}
	}
}

#[cfg(test)]
macro_rules! get_local_commitment_txn {
	($node: expr, $channel_id: expr) => {
		{
			let monitors = $node.chain_monitor.chain_monitor.monitors.read().unwrap();
			let mut commitment_txn = None;
			for (funding_txo, monitor) in monitors.iter() {
				if funding_txo.to_channel_id() == $channel_id {
					commitment_txn = Some(monitor.unsafe_get_latest_holder_commitment_txn(&$node.logger));
					break;
				}
			}
			commitment_txn.unwrap()
		}
	}
}

/// Check the error from attempting a payment.
#[macro_export]
macro_rules! unwrap_send_err {
	($res: expr, $all_failed: expr, $type: pat, $check: expr) => {
		match &$res {
			&Err(PaymentSendFailure::AllFailedRetrySafe(ref fails)) if $all_failed => {
				assert_eq!(fails.len(), 1);
				match fails[0] {
					$type => { $check },
					_ => panic!(),
				}
			},
			&Err(PaymentSendFailure::PartialFailure(ref fails)) if !$all_failed => {
				assert_eq!(fails.len(), 1);
				match fails[0] {
					Err($type) => { $check },
					_ => panic!(),
				}
			},
			_ => panic!(),
		}
	}
}

/// Check whether N channel monitor(s) have been added.
#[macro_export]
macro_rules! check_added_monitors {
	($node: expr, $count: expr) => {
		{
			let mut added_monitors = $node.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), $count);
			added_monitors.clear();
		}
	}
}

pub fn create_funding_transaction<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, expected_chan_value: u64, expected_user_chan_id: u64) -> ([u8; 32], Transaction, OutPoint) {
	let chan_id = *node.network_chan_count.borrow();

	let events = node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(*channel_value_satoshis, expected_chan_value);
			assert_eq!(user_channel_id, expected_user_chan_id);

			let tx = Transaction { version: chan_id as i32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
				value: *channel_value_satoshis, script_pubkey: output_script.clone(),
			}]};
			let funding_outpoint = OutPoint { txid: tx.txid(), index: 0 };
			(*temporary_channel_id, tx, funding_outpoint)
		},
		_ => panic!("Unexpected event"),
	}
}

pub fn create_chan_between_nodes_with_value_init<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> Transaction {
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42, None).unwrap();
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), a_flags, &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id()));
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), b_flags, &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id()));

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(node_a, channel_value, 42);

	node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(node_a, 0);

	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id()));
	{
		let mut added_monitors = node_b.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id()));
	{
		let mut added_monitors = node_a.chain_monitor.added_monitors.lock().unwrap();
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

pub fn create_chan_between_nodes_with_value_confirm_first<'a, 'b, 'c, 'd>(node_recv: &'a Node<'b, 'c, 'c>, node_conf: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
	confirm_transaction(node_conf, tx);
	node_recv.node.handle_funding_locked(&node_conf.node.get_our_node_id(), &get_event_msg!(node_conf, MessageSendEvent::SendFundingLocked, node_recv.node.get_our_node_id()));
}

pub fn create_chan_between_nodes_with_value_confirm_second<'a, 'b, 'c>(node_recv: &Node<'a, 'b, 'c>, node_conf: &Node<'a, 'b, 'c>) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
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

pub fn create_chan_between_nodes_with_value_confirm<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	create_chan_between_nodes_with_value_confirm_first(node_a, node_b, tx);
	confirm_transaction(node_a, tx);
	create_chan_between_nodes_with_value_confirm_second(node_b, node_a)
}

pub fn create_chan_between_nodes_with_value_a<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
	node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &as_funding_msgs.0);
	let bs_announcement_sigs = get_event_msg!(node_b, MessageSendEvent::SendAnnouncementSignatures, node_a.node.get_our_node_id());
	node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_funding_msgs.1);

	let events_7 = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(events_7.len(), 1);
	let (announcement, bs_update) = match events_7[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg, update_msg)
		},
		_ => panic!("Unexpected event"),
	};

	node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &bs_announcement_sigs);
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

pub fn create_announced_chan_between_nodes<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001, a_flags, b_flags)
}

pub fn create_announced_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat, a_flags, b_flags);
	update_nodes_with_chan_announce(nodes, a, b, &chan_announcement.0, &chan_announcement.1, &chan_announcement.2);
	(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
}

pub fn update_nodes_with_chan_announce<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, ann: &msgs::ChannelAnnouncement, upd_1: &msgs::ChannelUpdate, upd_2: &msgs::ChannelUpdate) {
	nodes[a].node.broadcast_node_announcement([0, 0, 0], [0; 32], Vec::new());
	let a_events = nodes[a].node.get_and_clear_pending_msg_events();
	assert_eq!(a_events.len(), 1);
	let a_node_announcement = match a_events[0] {
		MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[b].node.broadcast_node_announcement([1, 1, 1], [1; 32], Vec::new());
	let b_events = nodes[b].node.get_and_clear_pending_msg_events();
	assert_eq!(b_events.len(), 1);
	let b_node_announcement = match b_events[0] {
		MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	for node in nodes {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(ann).unwrap());
		node.net_graph_msg_handler.handle_channel_update(upd_1).unwrap();
		node.net_graph_msg_handler.handle_channel_update(upd_2).unwrap();
		node.net_graph_msg_handler.handle_node_announcement(&a_node_announcement).unwrap();
		node.net_graph_msg_handler.handle_node_announcement(&b_node_announcement).unwrap();
	}
}

macro_rules! check_spends {
	($tx: expr, $($spends_txn: expr),*) => {
		{
			let get_output = |out_point: &bitcoin::blockdata::transaction::OutPoint| {
				$(
					if out_point.txid == $spends_txn.txid() {
						return $spends_txn.output.get(out_point.vout as usize).cloned()
					}
				)*
				None
			};
			let mut total_value_in = 0;
			for input in $tx.input.iter() {
				total_value_in += get_output(&input.previous_output).unwrap().value;
			}
			let mut total_value_out = 0;
			for output in $tx.output.iter() {
				total_value_out += output.value;
			}
			let min_fee = ($tx.get_weight() as u64 + 3) / 4; // One sat per vbyte (ie per weight/4, rounded up)
			// Input amount - output amount = fee, so check that out + min_fee is smaller than input
			assert!(total_value_out + min_fee <= total_value_in);
			$tx.verify(get_output).unwrap();
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

/// Check that a channel's closing channel update has been broadcasted, and optionally
/// check whether an error message event has occurred.
#[macro_export]
macro_rules! check_closed_broadcast {
	($node: expr, $with_error_msg: expr) => {{
		let events = $node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), if $with_error_msg { 2 } else { 1 });
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
		if $with_error_msg {
			match events[1] {
				MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
					// TODO: Check node_id
					Some(msg.clone())
				},
				_ => panic!("Unexpected event"),
			}
		} else { None }
	}}
}

pub fn close_channel<'a, 'b, 'c>(outbound_node: &Node<'a, 'b, 'c>, inbound_node: &Node<'a, 'b, 'c>, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
	let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
	let (node_b, broadcaster_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster) } else { (&inbound_node.node, &inbound_node.tx_broadcaster) };
	let (tx_a, tx_b);

	node_a.close_channel(channel_id).unwrap();
	node_b.handle_shutdown(&node_a.get_our_node_id(), &InitFeatures::known(), &get_event_msg!(struct_a, MessageSendEvent::SendShutdown, node_b.get_our_node_id()));

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

	node_a.handle_shutdown(&node_b.get_our_node_id(), &InitFeatures::known(), &shutdown_b);
	let (as_update, bs_update) = if close_inbound_first {
		assert!(node_a.get_and_clear_pending_msg_events().is_empty());
		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap());
		let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
		assert!(none_b.is_none());
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		(as_update, bs_update)
	} else {
		let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a);
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
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

	pub fn from_node<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>) -> SendEvent {
		let mut events = node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.pop().unwrap())
	}
}

macro_rules! commitment_signed_dance {
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */) => {
		{
			check_added_monitors!($node_a, 0);
			assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed);
			check_added_monitors!($node_a, 1);
			commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, false);
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */, true /* return last RAA */) => {
		{
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!($node_a, $node_b.node.get_our_node_id());
			check_added_monitors!($node_b, 0);
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			$node_b.node.handle_revoke_and_ack(&$node_a.node.get_our_node_id(), &as_revoke_and_ack);
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors!($node_b, 1);
			$node_b.node.handle_commitment_signed(&$node_a.node.get_our_node_id(), &as_commitment_signed);
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
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed);
			check_added_monitors!($node_a, 1);
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			assert!(extra_msg_option.is_none());
			bs_revoke_and_ack
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */) => {
		{
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			$node_a.node.handle_revoke_and_ack(&$node_b.node.get_our_node_id(), &bs_revoke_and_ack);
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

/// Get a payment preimage and hash.
#[macro_export]
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

macro_rules! expect_pending_htlcs_forwardable_ignore {
	($node: expr) => {{
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}}
}

macro_rules! expect_pending_htlcs_forwardable {
	($node: expr) => {{
		expect_pending_htlcs_forwardable_ignore!($node);
		$node.node.process_pending_htlc_forwards();
	}}
}

#[cfg(test)]
macro_rules! expect_payment_received {
	($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
				assert_eq!($expected_payment_hash, *payment_hash);
				assert_eq!(None, *payment_secret);
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

#[cfg(test)]
macro_rules! expect_payment_failed {
	($node: expr, $expected_payment_hash: expr, $rejected_by_dest: expr $(, $expected_error_code: expr, $expected_error_data: expr)*) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { ref payment_hash, rejected_by_dest, ref error_code, ref error_data } => {
				assert_eq!(*payment_hash, $expected_payment_hash);
				assert_eq!(rejected_by_dest, $rejected_by_dest);
				assert!(error_code.is_some());
				assert!(error_data.is_some());
				$(
					assert_eq!(error_code.unwrap(), $expected_error_code);
					assert_eq!(&error_data.as_ref().unwrap()[..], $expected_error_data);
				)*
			},
			_ => panic!("Unexpected event"),
		}
	}
}

pub fn send_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_paths: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>) {
	origin_node.node.send_payment(&route, our_payment_hash, &our_payment_secret).unwrap();
	check_added_monitors!(origin_node, expected_paths.len());
	pass_along_route(origin_node, expected_paths, recv_value, our_payment_hash, our_payment_secret);
}

pub fn pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool) {
	let mut payment_event = SendEvent::from_event(ev);
	let mut prev_node = origin_node;

	for (idx, &node) in expected_path.iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(node);

		if idx == expected_path.len() - 1 {
			let events_2 = node.node.get_and_clear_pending_events();
			if payment_received_expected {
				assert_eq!(events_2.len(), 1);
				match events_2[0] {
					Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
						assert_eq!(our_payment_hash, *payment_hash);
						assert_eq!(our_payment_secret, *payment_secret);
						assert_eq!(amt, recv_value);
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				assert!(events_2.is_empty());
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

pub fn pass_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>) {
	let mut events = origin_node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_route.len());
	for (path_idx, (ev, expected_path)) in events.drain(..).zip(expected_route.iter()).enumerate() {
		// Once we've gotten through all the HTLCs, the last one should result in a
		// PaymentReceived (but each previous one should not!), .
		let expect_payment = path_idx == expected_route.len() - 1;
		pass_along_path(origin_node, expected_path, recv_value, our_payment_hash.clone(), our_payment_secret, ev, expect_payment);
	}
}

pub fn send_along_route_with_hash<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash) {
	send_along_route_with_secret(origin_node, route, &[expected_route], recv_value, our_payment_hash, None);
}

pub fn send_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	send_along_route_with_hash(origin_node, route, expected_route, recv_value, our_payment_hash);
	(our_payment_preimage, our_payment_hash)
}

pub fn claim_payment_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_preimage: PaymentPreimage, our_payment_secret: Option<PaymentSecret>, expected_amount: u64) {
	for path in expected_paths.iter() {
		assert_eq!(path.last().unwrap().node.get_our_node_id(), expected_paths[0].last().unwrap().node.get_our_node_id());
	}
	assert!(expected_paths[0].last().unwrap().node.claim_funds(our_payment_preimage, &our_payment_secret, expected_amount));
	check_added_monitors!(expected_paths[0].last().unwrap(), expected_paths.len());

	macro_rules! msgs_from_ev {
		($ev: expr) => {
			match $ev {
				&MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
					assert!(update_add_htlcs.is_empty());
					assert_eq!(update_fulfill_htlcs.len(), 1);
					assert!(update_fail_htlcs.is_empty());
					assert!(update_fail_malformed_htlcs.is_empty());
					assert!(update_fee.is_none());
					((update_fulfill_htlcs[0].clone(), commitment_signed.clone()), node_id.clone())
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
	let mut per_path_msgs: Vec<((msgs::UpdateFulfillHTLC, msgs::CommitmentSigned), PublicKey)> = Vec::with_capacity(expected_paths.len());
	let events = expected_paths[0].last().unwrap().node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());
	for ev in events.iter() {
		per_path_msgs.push(msgs_from_ev!(ev));
	}

	for (expected_route, (path_msgs, next_hop)) in expected_paths.iter().zip(per_path_msgs.drain(..)) {
		let mut next_msgs = Some(path_msgs);
		let mut expected_next_node = next_hop;

		macro_rules! last_update_fulfill_dance {
			($node: expr, $prev_node: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
					check_added_monitors!($node, 0);
					assert!($node.node.get_and_clear_pending_msg_events().is_empty());
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
				}
			}
		}
		macro_rules! mid_update_fulfill_dance {
			($node: expr, $prev_node: expr, $new_msgs: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
					check_added_monitors!($node, 1);
					let new_next_msgs = if $new_msgs {
						let events = $node.node.get_and_clear_pending_msg_events();
						assert_eq!(events.len(), 1);
						let (res, nexthop) = msgs_from_ev!(&events[0]);
						expected_next_node = nexthop;
						Some(res)
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
		for (idx, node) in expected_route.iter().rev().enumerate().skip(1) {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			let update_next_msgs = !skip_last || idx != expected_route.len() - 1;
			if next_msgs.is_some() {
				mid_update_fulfill_dance!(node, prev_node, update_next_msgs);
			} else {
				assert!(!update_next_msgs);
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
}

pub fn claim_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], skip_last: bool, our_payment_preimage: PaymentPreimage, expected_amount: u64) {
	claim_payment_along_route_with_secret(origin_node, &[expected_route], skip_last, our_payment_preimage, None, expected_amount);
}

pub fn claim_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], our_payment_preimage: PaymentPreimage, expected_amount: u64) {
	claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage, expected_amount);
}

pub const TEST_FINAL_CLTV: u32 = 32;

pub fn route_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let net_graph_msg_handler = &origin_node.net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&origin_node.node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV, &logger).unwrap();
	assert_eq!(route.paths.len(), 1);
	assert_eq!(route.paths[0].len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	send_along_route(origin_node, route, expected_route, recv_value)
}

pub fn route_over_limit<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64)  {
	let logger = test_utils::TestLogger::new();
	let net_graph_msg_handler = &origin_node.net_graph_msg_handler;
	let route = get_route(&origin_node.node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV, &logger).unwrap();
	assert_eq!(route.paths.len(), 1);
	assert_eq!(route.paths[0].len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	let (_, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	unwrap_send_err!(origin_node.node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert!(err.contains("Cannot send value that would put us over the max HTLC value in flight our peer will accept")));
}

pub fn send_payment<'a, 'b, 'c>(origin: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64, expected_value: u64)  {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage, expected_value);
}

pub fn fail_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], skip_last: bool, our_payment_hash: PaymentHash)  {
	assert!(expected_route.last().unwrap().node.fail_htlc_backwards(&our_payment_hash, &None));
	expect_pending_htlcs_forwardable!(expected_route.last().unwrap());
	check_added_monitors!(expected_route.last().unwrap(), 1);

	let mut next_msgs: Option<(msgs::UpdateFailHTLC, msgs::CommitmentSigned)> = None;
	macro_rules! update_fail_dance {
		($node: expr, $prev_node: expr, $last_node: expr) => {
			{
				$node.node.handle_update_fail_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
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

pub fn fail_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], our_payment_hash: PaymentHash)  {
	fail_payment_along_route(origin_node, expected_route, false, our_payment_hash);
}

pub fn create_chanmon_cfgs(node_count: usize) -> Vec<TestChanMonCfg> {
	let mut chan_mon_cfgs = Vec::new();
	for i in 0..node_count {
		let tx_broadcaster = test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())};
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
		let chain_source = test_utils::TestChainSource::new(Network::Testnet);
		let logger = test_utils::TestLogger::with_id(format!("node {}", i));
		let persister = test_utils::TestPersister::new();
		let seed = [i as u8; 32];
		let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);

		chan_mon_cfgs.push(TestChanMonCfg{ tx_broadcaster, fee_estimator, chain_source, logger, persister, keys_manager });
	}

	chan_mon_cfgs
}

pub fn create_node_cfgs<'a>(node_count: usize, chanmon_cfgs: &'a Vec<TestChanMonCfg>) -> Vec<NodeCfg<'a>> {
	let mut nodes = Vec::new();

	for i in 0..node_count {
		let chain_monitor = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[i].chain_source), &chanmon_cfgs[i].tx_broadcaster, &chanmon_cfgs[i].logger, &chanmon_cfgs[i].fee_estimator, &chanmon_cfgs[i].persister, &chanmon_cfgs[i].keys_manager);
		let seed = [i as u8; 32];
		nodes.push(NodeCfg { chain_source: &chanmon_cfgs[i].chain_source, logger: &chanmon_cfgs[i].logger, tx_broadcaster: &chanmon_cfgs[i].tx_broadcaster, fee_estimator: &chanmon_cfgs[i].fee_estimator, chain_monitor, keys_manager: &chanmon_cfgs[i].keys_manager, node_seed: seed });
	}

	nodes
}

pub fn create_node_chanmgrs<'a, 'b>(node_count: usize, cfgs: &'a Vec<NodeCfg<'b>>, node_config: &[Option<UserConfig>]) -> Vec<ChannelManager<EnforcingSigner, &'a TestChainMonitor<'b>, &'b test_utils::TestBroadcaster, &'a test_utils::TestKeysInterface, &'b test_utils::TestFeeEstimator, &'b test_utils::TestLogger>> {
	let mut chanmgrs = Vec::new();
	for i in 0..node_count {
		let mut default_config = UserConfig::default();
		default_config.channel_options.announced_channel = true;
		default_config.peer_channel_config_limits.force_announced_channel_preference = false;
		default_config.own_channel_config.our_htlc_minimum_msat = 1000; // sanitization being done by the sender, to exerce receiver logic we need to lift of limit
		let node = ChannelManager::new(Network::Testnet, cfgs[i].fee_estimator, &cfgs[i].chain_monitor, cfgs[i].tx_broadcaster, cfgs[i].logger, cfgs[i].keys_manager, if node_config[i].is_some() { node_config[i].clone().unwrap() } else { default_config }, 0);
		chanmgrs.push(node);
	}

	chanmgrs
}

pub fn create_network<'a, 'b: 'a, 'c: 'b>(node_count: usize, cfgs: &'b Vec<NodeCfg<'c>>, chan_mgrs: &'a Vec<ChannelManager<EnforcingSigner, &'b TestChainMonitor<'c>, &'c test_utils::TestBroadcaster, &'b test_utils::TestKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>>) -> Vec<Node<'a, 'b, 'c>> {
	let mut nodes = Vec::new();
	let chan_count = Rc::new(RefCell::new(0));
	let payment_count = Rc::new(RefCell::new(0));

	for i in 0..node_count {
		let net_graph_msg_handler = NetGraphMsgHandler::new(cfgs[i].chain_source.genesis_hash, None, cfgs[i].logger);
		nodes.push(Node{ chain_source: cfgs[i].chain_source,
		                 tx_broadcaster: cfgs[i].tx_broadcaster, chain_monitor: &cfgs[i].chain_monitor,
		                 keys_manager: &cfgs[i].keys_manager, node: &chan_mgrs[i], net_graph_msg_handler,
		                 node_seed: cfgs[i].node_seed, network_chan_count: chan_count.clone(),
		                 network_payment_count: payment_count.clone(), logger: cfgs[i].logger,
		})
	}

	nodes
}

pub const ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 138; //Here we have a diff due to HTLC CLTV expiry being < 2^15 in test
pub const OFFERED_HTLC_SCRIPT_WEIGHT: usize = 133;

#[derive(PartialEq)]
pub enum HTLCType { NONE, TIMEOUT, SUCCESS }
/// Tests that the given node has broadcast transactions for the given Channel
///
/// First checks that the latest holder commitment tx has been broadcast, unless an explicit
/// commitment_tx is provided, which may be used to test that a remote commitment tx was
/// broadcast and the revoked outputs were claimed.
///
/// Next tests that there is (or is not) a transaction that spends the commitment transaction
/// that appears to be the type of HTLC transaction specified in has_htlc_tx.
///
/// All broadcast transactions must be accounted for in one of the above three types of we'll
/// also fail.
pub fn test_txn_broadcast<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, chan: &(msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction), commitment_tx: Option<Transaction>, has_htlc_tx: HTLCType) -> Vec<Transaction>  {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(node_txn.len() >= if commitment_tx.is_some() { 0 } else { 1 } + if has_htlc_tx == HTLCType::NONE { 0 } else { 1 });

	let mut res = Vec::with_capacity(2);
	node_txn.retain(|tx| {
		if tx.input.len() == 1 && tx.input[0].previous_output.txid == chan.3.txid() {
			check_spends!(tx, chan.3);
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
				check_spends!(tx, res[0]);
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
pub fn test_revoked_htlc_claim_txn_broadcast<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, revoked_tx: Transaction, commitment_revoked_tx: Transaction)  {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
	// We may issue multiple claiming transaction on revoked outputs due to block rescan
	// for revoked htlc outputs
	if node_txn.len() != 1 && node_txn.len() != 2 && node_txn.len() != 3 { assert!(false); }
	node_txn.retain(|tx| {
		if tx.input.len() == 1 && tx.input[0].previous_output.txid == revoked_tx.txid() {
			check_spends!(tx, revoked_tx);
			false
		} else { true }
	});
	node_txn.retain(|tx| {
		check_spends!(tx, commitment_revoked_tx);
		false
	});
	assert!(node_txn.is_empty());
}

pub fn check_preimage_claim<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, prev_txn: &Vec<Transaction>) -> Vec<Transaction>  {
	let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();

	assert!(node_txn.len() >= 1);
	assert_eq!(node_txn[0].input.len(), 1);
	let mut found_prev = false;

	for tx in prev_txn {
		if node_txn[0].input[0].previous_output.txid == tx.txid() {
			check_spends!(node_txn[0], tx);
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

pub fn get_announce_close_broadcast_events<'a, 'b, 'c>(nodes: &Vec<Node<'a, 'b, 'c>>, a: usize, b: usize)  {
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
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}
}

#[cfg(test)]
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
pub fn reconnect_nodes<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, send_funding_locked: (bool, bool), pending_htlc_adds: (i64, i64), pending_htlc_claims: (usize, usize), pending_cell_htlc_claims: (usize, usize), pending_cell_htlc_fails: (usize, usize), pending_raa: (bool, bool))  {
	node_a.node.peer_connected(&node_b.node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(node_a, node_b);
	node_b.node.peer_connected(&node_a.node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
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
		// next_holder_commitment_number to 1
		for reestablish in reestablish_1.iter() {
			assert_eq!(reestablish.next_local_commitment_number, 1);
		}
		for reestablish in reestablish_2.iter() {
			assert_eq!(reestablish.next_local_commitment_number, 1);
		}
	}

	let mut resp_1 = Vec::new();
	for msg in reestablish_1 {
		node_b.node.handle_channel_reestablish(&node_a.node.get_our_node_id(), &msg);
		resp_1.push(handle_chan_reestablish_msgs!(node_b, node_a));
	}
	if pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
		check_added_monitors!(node_b, 1);
	} else {
		check_added_monitors!(node_b, 0);
	}

	let mut resp_2 = Vec::new();
	for msg in reestablish_2 {
		node_a.node.handle_channel_reestablish(&node_b.node.get_our_node_id(), &msg);
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
			node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &chan_msgs.0.unwrap());
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
			node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &chan_msgs.1.unwrap());
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
				node_a.node.handle_update_add_htlc(&node_b.node.get_our_node_id(), &update_add);
			}
			for update_fulfill in commitment_update.update_fulfill_htlcs {
				node_a.node.handle_update_fulfill_htlc(&node_b.node.get_our_node_id(), &update_fulfill);
			}
			for update_fail in commitment_update.update_fail_htlcs {
				node_a.node.handle_update_fail_htlc(&node_b.node.get_our_node_id(), &update_fail);
			}

			if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
				commitment_signed_dance!(node_a, node_b, commitment_update.commitment_signed, false);
			} else {
				node_a.node.handle_commitment_signed(&node_b.node.get_our_node_id(), &commitment_update.commitment_signed);
				check_added_monitors!(node_a, 1);
				let as_revoke_and_ack = get_event_msg!(node_a, MessageSendEvent::SendRevokeAndACK, node_b.node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &as_revoke_and_ack);
				assert!(node_b.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_b, 1);
			}
		} else {
			assert!(chan_msgs.2.is_none());
		}
	}

	for chan_msgs in resp_2.drain(..) {
		if send_funding_locked.1 {
			node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &chan_msgs.0.unwrap());
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
			node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &chan_msgs.1.unwrap());
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
				node_b.node.handle_update_add_htlc(&node_a.node.get_our_node_id(), &update_add);
			}
			for update_fulfill in commitment_update.update_fulfill_htlcs {
				node_b.node.handle_update_fulfill_htlc(&node_a.node.get_our_node_id(), &update_fulfill);
			}
			for update_fail in commitment_update.update_fail_htlcs {
				node_b.node.handle_update_fail_htlc(&node_a.node.get_our_node_id(), &update_fail);
			}

			if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
				commitment_signed_dance!(node_b, node_a, commitment_update.commitment_signed, false);
			} else {
				node_b.node.handle_commitment_signed(&node_a.node.get_our_node_id(), &commitment_update.commitment_signed);
				check_added_monitors!(node_b, 1);
				let bs_revoke_and_ack = get_event_msg!(node_b, MessageSendEvent::SendRevokeAndACK, node_a.node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &bs_revoke_and_ack);
				assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_a, 1);
			}
		} else {
			assert!(chan_msgs.2.is_none());
		}
	}
}
