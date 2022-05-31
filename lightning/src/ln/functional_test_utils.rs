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

use chain::{BestBlock, Confirm, Listen, Watch, keysinterface::KeysInterface};
use chain::channelmonitor::ChannelMonitor;
use chain::transaction::OutPoint;
use ln::{PaymentPreimage, PaymentHash, PaymentSecret};
use ln::channelmanager::{ChainParameters, ChannelManager, ChannelManagerReadArgs, RAACommitmentOrder, PaymentSendFailure, PaymentId, MIN_CLTV_EXPIRY_DELTA};
use routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
use routing::router::{PaymentParameters, Route, get_route};
use ln::features::{InitFeatures, InvoiceFeatures};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler};
use util::enforcing_trait_impls::EnforcingSigner;
use util::scid_utils;
use util::test_utils;
use util::test_utils::{panicking, TestChainMonitor};
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider, PaymentPurpose};
use util::errors::APIError;
use util::config::UserConfig;
use util::ser::{ReadableArgs, Writeable, Readable};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::network::constants::Network;

use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash as _;

use bitcoin::secp256k1::PublicKey;

use io;
use prelude::*;
use core::cell::RefCell;
use alloc::rc::Rc;
use sync::{Arc, Mutex};
use core::mem;

pub const CHAN_CONFIRM_DEPTH: u32 = 10;

/// Mine the given transaction in the next block and then mine CHAN_CONFIRM_DEPTH - 1 blocks on
/// top, giving the given transaction CHAN_CONFIRM_DEPTH confirmations.
///
/// Returns the SCID a channel confirmed in the given transaction will have, assuming the funding
/// output is the 1st output in the transaction.
pub fn confirm_transaction<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction) -> u64 {
	let scid = confirm_transaction_at(node, tx, node.best_block_info().1 + 1);
	connect_blocks(node, CHAN_CONFIRM_DEPTH - 1);
	scid
}
/// Mine a signle block containing the given transaction
pub fn mine_transaction<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
	let height = node.best_block_info().1 + 1;
	confirm_transaction_at(node, tx, height);
}
/// Mine the given transaction at the given height, mining blocks as required to build to that
/// height
///
/// Returns the SCID a channel confirmed in the given transaction will have, assuming the funding
/// output is the 1st output in the transaction.
pub fn confirm_transaction_at<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction, conf_height: u32) -> u64 {
	let first_connect_height = node.best_block_info().1 + 1;
	assert!(first_connect_height <= conf_height);
	if conf_height > first_connect_height {
		connect_blocks(node, conf_height - first_connect_height);
	}
	let mut block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: node.best_block_hash(), merkle_root: Default::default(), time: conf_height, bits: 42, nonce: 42 },
		txdata: Vec::new(),
	};
	for _ in 0..*node.network_chan_count.borrow() { // Make sure we don't end up with channels at the same short id by offsetting by chan_count
		block.txdata.push(Transaction { version: 0, lock_time: 0, input: Vec::new(), output: Vec::new() });
	}
	block.txdata.push(tx.clone());
	connect_block(node, &block);
	scid_utils::scid_from_parts(conf_height as u64, block.txdata.len() as u64 - 1, 0).unwrap()
}

/// The possible ways we may notify a ChannelManager of a new block
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectStyle {
	/// Calls `best_block_updated` first, detecting transactions in the block only after receiving
	/// the header and height information.
	BestBlockFirst,
	/// The same as `BestBlockFirst`, however when we have multiple blocks to connect, we only
	/// make a single `best_block_updated` call.
	BestBlockFirstSkippingBlocks,
	/// The same as `BestBlockFirst` when connecting blocks. During disconnection only
	/// `transaction_unconfirmed` is called.
	BestBlockFirstReorgsOnlyTip,
	/// Calls `transactions_confirmed` first, detecting transactions in the block before updating
	/// the header and height information.
	TransactionsFirst,
	/// The same as `TransactionsFirst`, however when we have multiple blocks to connect, we only
	/// make a single `best_block_updated` call.
	TransactionsFirstSkippingBlocks,
	/// The same as `TransactionsFirst` when connecting blocks. During disconnection only
	/// `transaction_unconfirmed` is called.
	TransactionsFirstReorgsOnlyTip,
	/// Provides the full block via the `chain::Listen` interface. In the current code this is
	/// equivalent to `TransactionsFirst` with some additional assertions.
	FullBlockViaListen,
}

impl ConnectStyle {
	fn random_style() -> ConnectStyle {
		#[cfg(feature = "std")] {
			use core::hash::{BuildHasher, Hasher};
			// Get a random value using the only std API to do so - the DefaultHasher
			let rand_val = std::collections::hash_map::RandomState::new().build_hasher().finish();
			let res = match rand_val % 7 {
				0 => ConnectStyle::BestBlockFirst,
				1 => ConnectStyle::BestBlockFirstSkippingBlocks,
				2 => ConnectStyle::BestBlockFirstReorgsOnlyTip,
				3 => ConnectStyle::TransactionsFirst,
				4 => ConnectStyle::TransactionsFirstSkippingBlocks,
				5 => ConnectStyle::TransactionsFirstReorgsOnlyTip,
				6 => ConnectStyle::FullBlockViaListen,
				_ => unreachable!(),
			};
			eprintln!("Using Block Connection Style: {:?}", res);
			res
		}
		#[cfg(not(feature = "std"))] {
			ConnectStyle::FullBlockViaListen
		}
	}
}

pub fn connect_blocks<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, depth: u32) -> BlockHash {
	let skip_intermediaries = match *node.connect_style.borrow() {
		ConnectStyle::BestBlockFirstSkippingBlocks|ConnectStyle::TransactionsFirstSkippingBlocks|
			ConnectStyle::BestBlockFirstReorgsOnlyTip|ConnectStyle::TransactionsFirstReorgsOnlyTip => true,
		_ => false,
	};

	let height = node.best_block_info().1 + 1;
	let mut block = Block {
		header: BlockHeader { version: 0x2000000, prev_blockhash: node.best_block_hash(), merkle_root: Default::default(), time: height, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	assert!(depth >= 1);
	for i in 1..depth {
		let prev_blockhash = block.header.block_hash();
		do_connect_block(node, block, skip_intermediaries);
		block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash, merkle_root: Default::default(), time: height + i, bits: 42, nonce: 42 },
			txdata: vec![],
		};
	}
	let hash = block.header.block_hash();
	do_connect_block(node, block, false);
	hash
}

pub fn connect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, block: &Block) {
	do_connect_block(node, block.clone(), false);
}

fn call_claimable_balances<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>) {
	// Ensure `get_claimable_balances`' self-tests never panic
	for funding_outpoint in node.chain_monitor.chain_monitor.list_monitors() {
		node.chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances();
	}
}

fn do_connect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, block: Block, skip_intermediaries: bool) {
	call_claimable_balances(node);
	let height = node.best_block_info().1 + 1;
	#[cfg(feature = "std")] {
		eprintln!("Connecting block using Block Connection Style: {:?}", *node.connect_style.borrow());
	}
	if !skip_intermediaries {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		match *node.connect_style.borrow() {
			ConnectStyle::BestBlockFirst|ConnectStyle::BestBlockFirstSkippingBlocks|ConnectStyle::BestBlockFirstReorgsOnlyTip => {
				node.chain_monitor.chain_monitor.best_block_updated(&block.header, height);
				call_claimable_balances(node);
				node.chain_monitor.chain_monitor.transactions_confirmed(&block.header, &txdata, height);
				node.node.best_block_updated(&block.header, height);
				node.node.transactions_confirmed(&block.header, &txdata, height);
			},
			ConnectStyle::TransactionsFirst|ConnectStyle::TransactionsFirstSkippingBlocks|ConnectStyle::TransactionsFirstReorgsOnlyTip => {
				node.chain_monitor.chain_monitor.transactions_confirmed(&block.header, &txdata, height);
				call_claimable_balances(node);
				node.chain_monitor.chain_monitor.best_block_updated(&block.header, height);
				node.node.transactions_confirmed(&block.header, &txdata, height);
				node.node.best_block_updated(&block.header, height);
			},
			ConnectStyle::FullBlockViaListen => {
				node.chain_monitor.chain_monitor.block_connected(&block, height);
				node.node.block_connected(&block, height);
			}
		}
	}
	call_claimable_balances(node);
	node.node.test_process_background_events();
	node.blocks.lock().unwrap().push((block, height));
}

pub fn disconnect_blocks<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, count: u32) {
	call_claimable_balances(node);
	#[cfg(feature = "std")] {
		eprintln!("Disconnecting {} blocks using Block Connection Style: {:?}", count, *node.connect_style.borrow());
	}
	for i in 0..count {
		let orig = node.blocks.lock().unwrap().pop().unwrap();
		assert!(orig.1 > 0); // Cannot disconnect genesis
		let prev = node.blocks.lock().unwrap().last().unwrap().clone();

		match *node.connect_style.borrow() {
			ConnectStyle::FullBlockViaListen => {
				node.chain_monitor.chain_monitor.block_disconnected(&orig.0.header, orig.1);
				Listen::block_disconnected(node.node, &orig.0.header, orig.1);
			},
			ConnectStyle::BestBlockFirstSkippingBlocks|ConnectStyle::TransactionsFirstSkippingBlocks => {
				if i == count - 1 {
					node.chain_monitor.chain_monitor.best_block_updated(&prev.0.header, prev.1);
					node.node.best_block_updated(&prev.0.header, prev.1);
				}
			},
			ConnectStyle::BestBlockFirstReorgsOnlyTip|ConnectStyle::TransactionsFirstReorgsOnlyTip => {
				for tx in orig.0.txdata {
					node.chain_monitor.chain_monitor.transaction_unconfirmed(&tx.txid());
					node.node.transaction_unconfirmed(&tx.txid());
				}
			},
			_ => {
				node.chain_monitor.chain_monitor.best_block_updated(&prev.0.header, prev.1);
				node.node.best_block_updated(&prev.0.header, prev.1);
			},
		}
		call_claimable_balances(node);
	}
}

pub fn disconnect_all_blocks<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>) {
	let count = node.blocks.lock().unwrap().len() as u32 - 1;
	disconnect_blocks(node, count);
}

pub struct TestChanMonCfg {
	pub tx_broadcaster: test_utils::TestBroadcaster,
	pub fee_estimator: test_utils::TestFeeEstimator,
	pub chain_source: test_utils::TestChainSource,
	pub persister: test_utils::TestPersister,
	pub logger: test_utils::TestLogger,
	pub keys_manager: test_utils::TestKeysInterface,
	pub network_graph: NetworkGraph,
}

pub struct NodeCfg<'a> {
	pub chain_source: &'a test_utils::TestChainSource,
	pub tx_broadcaster: &'a test_utils::TestBroadcaster,
	pub fee_estimator: &'a test_utils::TestFeeEstimator,
	pub chain_monitor: test_utils::TestChainMonitor<'a>,
	pub keys_manager: &'a test_utils::TestKeysInterface,
	pub logger: &'a test_utils::TestLogger,
	pub network_graph: &'a NetworkGraph,
	pub node_seed: [u8; 32],
	pub features: InitFeatures,
}

pub struct Node<'a, 'b: 'a, 'c: 'b> {
	pub chain_source: &'c test_utils::TestChainSource,
	pub tx_broadcaster: &'c test_utils::TestBroadcaster,
	pub chain_monitor: &'b test_utils::TestChainMonitor<'c>,
	pub keys_manager: &'b test_utils::TestKeysInterface,
	pub node: &'a ChannelManager<EnforcingSigner, &'b TestChainMonitor<'c>, &'c test_utils::TestBroadcaster, &'b test_utils::TestKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>,
	pub network_graph: &'c NetworkGraph,
	pub net_graph_msg_handler: NetGraphMsgHandler<&'c NetworkGraph, &'c test_utils::TestChainSource, &'c test_utils::TestLogger>,
	pub node_seed: [u8; 32],
	pub network_payment_count: Rc<RefCell<u8>>,
	pub network_chan_count: Rc<RefCell<u32>>,
	pub logger: &'c test_utils::TestLogger,
	pub blocks: Arc<Mutex<Vec<(Block, u32)>>>,
	pub connect_style: Rc<RefCell<ConnectStyle>>,
}
impl<'a, 'b, 'c> Node<'a, 'b, 'c> {
	pub fn best_block_hash(&self) -> BlockHash {
		self.blocks.lock().unwrap().last().unwrap().0.block_hash()
	}
	pub fn best_block_info(&self) -> (BlockHash, u32) {
		self.blocks.lock().unwrap().last().map(|(a, b)| (a.block_hash(), *b)).unwrap()
	}
	pub fn get_block_header(&self, height: u32) -> BlockHeader {
		self.blocks.lock().unwrap()[height as usize].0.header
	}
}

impl<'a, 'b, 'c> Drop for Node<'a, 'b, 'c> {
	fn drop(&mut self) {
		if !panicking() {
			// Check that we processed all pending events
			assert!(self.node.get_and_clear_pending_msg_events().is_empty());
			assert!(self.node.get_and_clear_pending_events().is_empty());
			assert!(self.chain_monitor.added_monitors.lock().unwrap().is_empty());

			// Check that if we serialize the Router, we can deserialize it again.
			{
				let mut w = test_utils::TestVecWriter(Vec::new());
				self.network_graph.write(&mut w).unwrap();
				let network_graph_deser = <NetworkGraph>::read(&mut io::Cursor::new(&w.0)).unwrap();
				assert!(network_graph_deser == *self.network_graph);
				let net_graph_msg_handler = NetGraphMsgHandler::new(
					&network_graph_deser, Some(self.chain_source), self.logger
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
			let feeest = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };
			let mut deserialized_monitors = Vec::new();
			{
				for outpoint in self.chain_monitor.chain_monitor.list_monitors() {
					let mut w = test_utils::TestVecWriter(Vec::new());
					self.chain_monitor.chain_monitor.get_monitor(outpoint).unwrap().write(&mut w).unwrap();
					let (_, deserialized_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
						&mut io::Cursor::new(&w.0), self.keys_manager).unwrap();
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
				<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut io::Cursor::new(w.0), ChannelManagerReadArgs {
					default_config: *self.node.get_current_default_configuration(),
					keys_manager: self.keys_manager,
					fee_estimator: &test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) },
					chain_monitor: self.chain_monitor,
					tx_broadcaster: &test_utils::TestBroadcaster {
						txn_broadcasted: Mutex::new(self.tx_broadcaster.txn_broadcasted.lock().unwrap().clone()),
						blocks: Arc::new(Mutex::new(self.tx_broadcaster.blocks.lock().unwrap().clone())),
					},
					logger: &self.logger,
					channel_monitors,
				}).unwrap();
			}

			let persister = test_utils::TestPersister::new();
			let broadcaster = test_utils::TestBroadcaster {
				txn_broadcasted: Mutex::new(self.tx_broadcaster.txn_broadcasted.lock().unwrap().clone()),
				blocks: Arc::new(Mutex::new(self.tx_broadcaster.blocks.lock().unwrap().clone())),
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
	let (channel_ready, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(node_a, node_b, &channel_ready);
	(announcement, as_update, bs_update, channel_id, tx)
}

#[macro_export]
/// Gets an RAA and CS which were sent in response to a commitment update
macro_rules! get_revoke_commit_msgs {
	($node: expr, $node_id: expr) => {
		{
			use $crate::util::events::MessageSendEvent;
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

/// Get an error message from the pending events queue.
#[macro_export]
macro_rules! get_err_msg {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$crate::util::events::MessageSendEvent::HandleError {
					action: $crate::ln::msgs::ErrorAction::SendErrorMessage { ref msg }, ref node_id
				} => {
					assert_eq!(*node_id, $node_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

/// Get a specific event from the pending events queue.
#[macro_export]
macro_rules! get_event {
	($node: expr, $event_type: path) => {
		{
			let mut events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let ev = events.pop().unwrap();
			match ev {
				$event_type { .. } => {
					ev
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

#[macro_export]
/// Gets an UpdateHTLCs MessageSendEvent
macro_rules! get_htlc_update_msgs {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$crate::util::events::MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
					assert_eq!(*node_id, $node_id);
					(*updates).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

#[cfg(test)]
macro_rules! get_channel_ref {
	($node: expr, $lock: ident, $channel_id: expr) => {
		{
			$lock = $node.node.channel_state.lock().unwrap();
			$lock.by_id.get_mut(&$channel_id).unwrap()
		}
	}
}

#[cfg(test)]
macro_rules! get_feerate {
	($node: expr, $channel_id: expr) => {
		{
			let mut lock;
			let chan = get_channel_ref!($node, lock, $channel_id);
			chan.get_feerate()
		}
	}
}

#[cfg(test)]
macro_rules! get_opt_anchors {
	($node: expr, $channel_id: expr) => {
		{
			let mut lock;
			let chan = get_channel_ref!($node, lock, $channel_id);
			chan.opt_anchors()
		}
	}
}

/// Returns a channel monitor given a channel id, making some naive assumptions
#[macro_export]
macro_rules! get_monitor {
	($node: expr, $channel_id: expr) => {
		{
			use bitcoin::hashes::Hash;
			let mut monitor = None;
			// Assume funding vout is either 0 or 1 blindly
			for index in 0..2 {
				if let Ok(mon) = $node.chain_monitor.chain_monitor.get_monitor(
					$crate::chain::transaction::OutPoint {
						txid: bitcoin::Txid::from_slice(&$channel_id[..]).unwrap(), index
					})
				{
					monitor = Some(mon);
					break;
				}
			}
			monitor.unwrap()
		}
	}
}

/// Returns any local commitment transactions for the channel.
#[macro_export]
macro_rules! get_local_commitment_txn {
	($node: expr, $channel_id: expr) => {
		{
			$crate::get_monitor!($node, $channel_id).unsafe_get_latest_holder_commitment_txn(&$node.logger)
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
			&Err(PaymentSendFailure::PartialFailure { ref results, .. }) if !$all_failed => {
				assert_eq!(results.len(), 1);
				match results[0] {
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

pub fn create_funding_transaction<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, expected_counterparty_node_id: &PublicKey, expected_chan_value: u64, expected_user_chan_id: u64) -> ([u8; 32], Transaction, OutPoint) {
	let chan_id = *node.network_chan_count.borrow();

	let events = node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref counterparty_node_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(counterparty_node_id, expected_counterparty_node_id);
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
pub fn sign_funding_transaction<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, channel_value: u64, expected_temporary_channel_id: [u8; 32]) -> Transaction {
	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(node_a, &node_b.node.get_our_node_id(), channel_value, 42);
	assert_eq!(temporary_channel_id, expected_temporary_channel_id);

	assert!(node_a.node.funding_transaction_generated(&temporary_channel_id, &node_b.node.get_our_node_id(), tx.clone()).is_ok());
	check_added_monitors!(node_a, 0);

	let funding_created_msg = get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id());
	assert_eq!(funding_created_msg.temporary_channel_id, expected_temporary_channel_id);
	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &funding_created_msg);
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
	assert_eq!(events_4.len(), 0);

	assert_eq!(node_a.tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(node_a.tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);
	node_a.tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

	// Ensure that funding_transaction_generated is idempotent.
	assert!(node_a.node.funding_transaction_generated(&temporary_channel_id, &node_b.node.get_our_node_id(), tx.clone()).is_err());
	assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(node_a, 0);

	tx
}

pub fn create_chan_between_nodes_with_value_init<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> Transaction {
	let create_chan_id = node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42, None).unwrap();
	let open_channel_msg = get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id());
	assert_eq!(open_channel_msg.temporary_channel_id, create_chan_id);
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), a_flags, &open_channel_msg);
	let accept_channel_msg = get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id());
	assert_eq!(accept_channel_msg.temporary_channel_id, create_chan_id);
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), b_flags, &accept_channel_msg);

	sign_funding_transaction(node_a, node_b, channel_value, create_chan_id)
}

pub fn create_chan_between_nodes_with_value_confirm_first<'a, 'b, 'c, 'd>(node_recv: &'a Node<'b, 'c, 'c>, node_conf: &'a Node<'b, 'c, 'd>, tx: &Transaction, conf_height: u32) {
	confirm_transaction_at(node_conf, tx, conf_height);
	connect_blocks(node_conf, CHAN_CONFIRM_DEPTH - 1);
	node_recv.node.handle_channel_ready(&node_conf.node.get_our_node_id(), &get_event_msg!(node_conf, MessageSendEvent::SendChannelReady, node_recv.node.get_our_node_id()));
}

pub fn create_chan_between_nodes_with_value_confirm_second<'a, 'b, 'c>(node_recv: &Node<'a, 'b, 'c>, node_conf: &Node<'a, 'b, 'c>) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32]) {
	let channel_id;
	let events_6 = node_conf.node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 3);
	let announcement_sigs_idx = if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = events_6[1] {
		assert_eq!(*node_id, node_recv.node.get_our_node_id());
		2
	} else if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = events_6[2] {
		assert_eq!(*node_id, node_recv.node.get_our_node_id());
		1
	} else { panic!("Unexpected event: {:?}", events_6[1]); };
	((match events_6[0] {
		MessageSendEvent::SendChannelReady { ref node_id, ref msg } => {
			channel_id = msg.channel_id.clone();
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}, match events_6[announcement_sigs_idx] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}), channel_id)
}

pub fn create_chan_between_nodes_with_value_confirm<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, tx: &Transaction) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32]) {
	let conf_height = core::cmp::max(node_a.best_block_info().1 + 1, node_b.best_block_info().1 + 1);
	create_chan_between_nodes_with_value_confirm_first(node_a, node_b, tx, conf_height);
	confirm_transaction_at(node_a, tx, conf_height);
	connect_blocks(node_a, CHAN_CONFIRM_DEPTH - 1);
	create_chan_between_nodes_with_value_confirm_second(node_b, node_a)
}

pub fn create_chan_between_nodes_with_value_a<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, as_funding_msgs: &(msgs::ChannelReady, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
	node_b.node.handle_channel_ready(&node_a.node.get_our_node_id(), &as_funding_msgs.0);
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

pub fn create_unannounced_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelReady, Transaction) {
	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.channel_options.announced_channel = false;
	nodes[a].node.create_channel(nodes[b].node.get_our_node_id(), channel_value, push_msat, 42, Some(no_announce_cfg)).unwrap();
	let open_channel = get_event_msg!(nodes[a], MessageSendEvent::SendOpenChannel, nodes[b].node.get_our_node_id());
	nodes[b].node.handle_open_channel(&nodes[a].node.get_our_node_id(), a_flags, &open_channel);
	let accept_channel = get_event_msg!(nodes[b], MessageSendEvent::SendAcceptChannel, nodes[a].node.get_our_node_id());
	nodes[a].node.handle_accept_channel(&nodes[b].node.get_our_node_id(), b_flags, &accept_channel);

	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[a], &nodes[b].node.get_our_node_id(), channel_value, 42);
	nodes[a].node.funding_transaction_generated(&temporary_channel_id, &nodes[b].node.get_our_node_id(), tx.clone()).unwrap();
	nodes[b].node.handle_funding_created(&nodes[a].node.get_our_node_id(), &get_event_msg!(nodes[a], MessageSendEvent::SendFundingCreated, nodes[b].node.get_our_node_id()));
	check_added_monitors!(nodes[b], 1);

	let cs_funding_signed = get_event_msg!(nodes[b], MessageSendEvent::SendFundingSigned, nodes[a].node.get_our_node_id());
	nodes[a].node.handle_funding_signed(&nodes[b].node.get_our_node_id(), &cs_funding_signed);
	check_added_monitors!(nodes[a], 1);

	let conf_height = core::cmp::max(nodes[a].best_block_info().1 + 1, nodes[b].best_block_info().1 + 1);
	confirm_transaction_at(&nodes[a], &tx, conf_height);
	connect_blocks(&nodes[a], CHAN_CONFIRM_DEPTH - 1);
	confirm_transaction_at(&nodes[b], &tx, conf_height);
	connect_blocks(&nodes[b], CHAN_CONFIRM_DEPTH - 1);
	let as_channel_ready = get_event_msg!(nodes[a], MessageSendEvent::SendChannelReady, nodes[b].node.get_our_node_id());
	nodes[a].node.handle_channel_ready(&nodes[b].node.get_our_node_id(), &get_event_msg!(nodes[b], MessageSendEvent::SendChannelReady, nodes[a].node.get_our_node_id()));
	let as_update = get_event_msg!(nodes[a], MessageSendEvent::SendChannelUpdate, nodes[b].node.get_our_node_id());
	nodes[b].node.handle_channel_ready(&nodes[a].node.get_our_node_id(), &as_channel_ready);
	let bs_update = get_event_msg!(nodes[b], MessageSendEvent::SendChannelUpdate, nodes[a].node.get_our_node_id());

	nodes[a].node.handle_channel_update(&nodes[b].node.get_our_node_id(), &bs_update);
	nodes[b].node.handle_channel_update(&nodes[a].node.get_our_node_id(), &as_update);

	let mut found_a = false;
	for chan in nodes[a].node.list_usable_channels() {
		if chan.channel_id == as_channel_ready.channel_id {
			assert!(!found_a);
			found_a = true;
			assert!(!chan.is_public);
		}
	}
	assert!(found_a);

	let mut found_b = false;
	for chan in nodes[b].node.list_usable_channels() {
		if chan.channel_id == as_channel_ready.channel_id {
			assert!(!found_b);
			found_b = true;
			assert!(!chan.is_public);
		}
	}
	assert!(found_b);

	(as_channel_ready, tx)
}

pub fn update_nodes_with_chan_announce<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, ann: &msgs::ChannelAnnouncement, upd_1: &msgs::ChannelUpdate, upd_2: &msgs::ChannelUpdate) {
	nodes[a].node.broadcast_node_announcement([0, 0, 0], [0; 32], Vec::new());
	let a_events = nodes[a].node.get_and_clear_pending_msg_events();
	assert!(a_events.len() >= 2);

	// ann should be re-generated by broadcast_node_announcement - check that we have it.
	let mut found_ann_1 = false;
	for event in a_events.iter() {
		match event {
			MessageSendEvent::BroadcastChannelAnnouncement { ref msg, .. } => {
				if msg == ann { found_ann_1 = true; }
			},
			MessageSendEvent::BroadcastNodeAnnouncement { .. } => {},
			_ => panic!("Unexpected event {:?}", event),
		}
	}
	assert!(found_ann_1);

	let a_node_announcement = match a_events.last().unwrap() {
		MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[b].node.broadcast_node_announcement([1, 1, 1], [1; 32], Vec::new());
	let b_events = nodes[b].node.get_and_clear_pending_msg_events();
	assert!(b_events.len() >= 2);

	// ann should be re-generated by broadcast_node_announcement - check that we have it.
	let mut found_ann_2 = false;
	for event in b_events.iter() {
		match event {
			MessageSendEvent::BroadcastChannelAnnouncement { ref msg, .. } => {
				if msg == ann { found_ann_2 = true; }
			},
			MessageSendEvent::BroadcastNodeAnnouncement { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
	assert!(found_ann_2);

	let b_node_announcement = match b_events.last().unwrap() {
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

		// Note that channel_updates are also delivered to ChannelManagers to ensure we have
		// forwarding info for local channels even if its not accepted in the network graph.
		node.node.handle_channel_update(&nodes[a].node.get_our_node_id(), &upd_1);
		node.node.handle_channel_update(&nodes[b].node.get_our_node_id(), &upd_2);
	}
}

#[macro_export]
macro_rules! check_spends {
	($tx: expr, $($spends_txn: expr),*) => {
		{
			$(
			for outp in $spends_txn.output.iter() {
				assert!(outp.value >= outp.script_pubkey.dust_value().as_sat(), "Input tx output didn't meet dust limit");
			}
			)*
			for outp in $tx.output.iter() {
				assert!(outp.value >= outp.script_pubkey.dust_value().as_sat(), "Spending tx output didn't meet dust limit");
			}
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
			let min_fee = ($tx.weight() as u64 + 3) / 4; // One sat per vbyte (ie per weight/4, rounded up)
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

#[cfg(test)]
macro_rules! check_warn_msg {
	($node: expr, $recipient_node_id: expr, $chan_id: expr) => {{
		let msg_events = $node.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		match msg_events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendWarningMessage { ref msg, log_level: _ }, node_id } => {
				assert_eq!(node_id, $recipient_node_id);
				assert_eq!(msg.channel_id, $chan_id);
				msg.data.clone()
			},
			_ => panic!("Unexpected event"),
		}
	}}
}

/// Check that a channel's closing channel update has been broadcasted, and optionally
/// check whether an error message event has occurred.
#[macro_export]
macro_rules! check_closed_broadcast {
	($node: expr, $with_error_msg: expr) => {{
		use $crate::util::events::MessageSendEvent;
		use $crate::ln::msgs::ErrorAction;

		let msg_events = $node.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), if $with_error_msg { 2 } else { 1 });
		match msg_events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
		if $with_error_msg {
			match msg_events[1] {
				MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
					// TODO: Check node_id
					Some(msg.clone())
				},
				_ => panic!("Unexpected event"),
			}
		} else { None }
	}}
}

/// Check that a channel's closing channel events has been issued
#[macro_export]
macro_rules! check_closed_event {
	($node: expr, $events: expr, $reason: expr) => {
		check_closed_event!($node, $events, $reason, false);
	};
	($node: expr, $events: expr, $reason: expr, $is_check_discard_funding: expr) => {{
		use $crate::util::events::Event;

		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), $events);
		let expected_reason = $reason;
		let mut issues_discard_funding = false;
		for event in events {
			match event {
				Event::ChannelClosed { ref reason, .. } => {
					assert_eq!(*reason, expected_reason);
				},
				Event::DiscardFunding { .. } => {
					issues_discard_funding = true;
				}
				_ => panic!("Unexpected event"),
			}
		}
		assert_eq!($is_check_discard_funding, issues_discard_funding);
	}}
}

pub fn close_channel<'a, 'b, 'c>(outbound_node: &Node<'a, 'b, 'c>, inbound_node: &Node<'a, 'b, 'c>, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
	let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
	let (node_b, broadcaster_b, struct_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) } else { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) };
	let (tx_a, tx_b);

	node_a.close_channel(channel_id, &node_b.get_our_node_id()).unwrap();
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

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id()));
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
		let (as_update, none_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());
		assert!(none_a.is_none());
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		(as_update, bs_update)
	} else {
		let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a);
		node_a.handle_closing_signed(&node_b.get_our_node_id(), &get_event_msg!(struct_b, MessageSendEvent::SendClosingSigned, node_a.get_our_node_id()));

		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap());
		let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
		assert!(none_b.is_none());
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
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

#[macro_export]
/// Performs the "commitment signed dance" - the series of message exchanges which occur after a
/// commitment update.
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
				$crate::expect_pending_htlcs_forwardable!($node_a);
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
	($dest_node: expr) => {
		{
			get_payment_preimage_hash!($dest_node, None)
		}
	};
	($dest_node: expr, $min_value_msat: expr) => {
		{
			use bitcoin::hashes::Hash as _;
			let mut payment_count = $dest_node.network_payment_count.borrow_mut();
			let payment_preimage = $crate::ln::PaymentPreimage([*payment_count; 32]);
			*payment_count += 1;
			let payment_hash = $crate::ln::PaymentHash(
				bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0[..]).into_inner());
			let payment_secret = $dest_node.node.create_inbound_payment_for_hash(payment_hash, $min_value_msat, 7200).unwrap();
			(payment_preimage, payment_hash, payment_secret)
		}
	}
}

#[macro_export]
macro_rules! get_route {
	($send_node: expr, $payment_params: expr, $recv_value: expr, $cltv: expr) => {{
		use $crate::chain::keysinterface::KeysInterface;
		let scorer = $crate::util::test_utils::TestScorer::with_penalty(0);
		let keys_manager = $crate::util::test_utils::TestKeysInterface::new(&[0u8; 32], bitcoin::network::constants::Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		$crate::routing::router::get_route(
			&$send_node.node.get_our_node_id(), &$payment_params, &$send_node.network_graph.read_only(),
			Some(&$send_node.node.list_usable_channels().iter().collect::<Vec<_>>()),
			$recv_value, $cltv, $send_node.logger, &scorer, &random_seed_bytes
		)
	}}
}

#[cfg(test)]
#[macro_export]
macro_rules! get_route_and_payment_hash {
	($send_node: expr, $recv_node: expr, $recv_value: expr) => {{
		let payment_params = $crate::routing::router::PaymentParameters::from_node_id($recv_node.node.get_our_node_id())
			.with_features($crate::ln::features::InvoiceFeatures::known());
		$crate::get_route_and_payment_hash!($send_node, $recv_node, payment_params, $recv_value, TEST_FINAL_CLTV)
	}};
	($send_node: expr, $recv_node: expr, $payment_params: expr, $recv_value: expr, $cltv: expr) => {{
		let (payment_preimage, payment_hash, payment_secret) = $crate::get_payment_preimage_hash!($recv_node, Some($recv_value));
		let route = $crate::get_route!($send_node, $payment_params, $recv_value, $cltv);
		(route.unwrap(), payment_hash, payment_preimage, payment_secret)
	}}
}

#[macro_export]
/// Clears (and ignores) a PendingHTLCsForwardable event
macro_rules! expect_pending_htlcs_forwardable_ignore {
	($node: expr) => {{
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			$crate::util::events::Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}}
}

#[macro_export]
/// Handles a PendingHTLCsForwardable event
macro_rules! expect_pending_htlcs_forwardable {
	($node: expr) => {{
		$crate::expect_pending_htlcs_forwardable_ignore!($node);
		$node.node.process_pending_htlc_forwards();

		// Ensure process_pending_htlc_forwards is idempotent.
		$node.node.process_pending_htlc_forwards();
	}}
}

#[cfg(test)]
macro_rules! expect_pending_htlcs_forwardable_from_events {
	($node: expr, $events: expr, $ignore: expr) => {{
		assert_eq!($events.len(), 1);
		match $events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		if $ignore {
			$node.node.process_pending_htlc_forwards();

			// Ensure process_pending_htlc_forwards is idempotent.
			$node.node.process_pending_htlc_forwards();
		}
	}}
}

#[macro_export]
#[cfg(any(test, feature = "_bench_unstable", feature = "_test_utils"))]
macro_rules! expect_payment_received {
	($node: expr, $expected_payment_hash: expr, $expected_payment_secret: expr, $expected_recv_value: expr) => {
		expect_payment_received!($node, $expected_payment_hash, $expected_payment_secret, $expected_recv_value, None)
	};
	($node: expr, $expected_payment_hash: expr, $expected_payment_secret: expr, $expected_recv_value: expr, $expected_payment_preimage: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			$crate::util::events::Event::PaymentReceived { ref payment_hash, ref purpose, amount_msat } => {
				assert_eq!($expected_payment_hash, *payment_hash);
				assert_eq!($expected_recv_value, amount_msat);
				match purpose {
					$crate::util::events::PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
						assert_eq!(&$expected_payment_preimage, payment_preimage);
						assert_eq!($expected_payment_secret, *payment_secret);
					},
					_ => {},
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[macro_export]
#[cfg(any(test, feature = "_bench_unstable", feature = "_test_utils"))]
macro_rules! expect_payment_claimed {
	($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			$crate::util::events::Event::PaymentClaimed { ref payment_hash, amount_msat, .. } => {
				assert_eq!($expected_payment_hash, *payment_hash);
				assert_eq!($expected_recv_value, amount_msat);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[cfg(test)]
#[macro_export]
macro_rules! expect_payment_sent_without_paths {
	($node: expr, $expected_payment_preimage: expr) => {
		expect_payment_sent!($node, $expected_payment_preimage, None::<u64>, false);
	};
	($node: expr, $expected_payment_preimage: expr, $expected_fee_msat_opt: expr) => {
		expect_payment_sent!($node, $expected_payment_preimage, $expected_fee_msat_opt, false);
	}
}

#[macro_export]
macro_rules! expect_payment_sent {
	($node: expr, $expected_payment_preimage: expr) => {
		$crate::expect_payment_sent!($node, $expected_payment_preimage, None::<u64>, true);
	};
	($node: expr, $expected_payment_preimage: expr, $expected_fee_msat_opt: expr) => {
		$crate::expect_payment_sent!($node, $expected_payment_preimage, $expected_fee_msat_opt, true);
	};
	($node: expr, $expected_payment_preimage: expr, $expected_fee_msat_opt: expr, $expect_paths: expr) => { {
		use bitcoin::hashes::Hash as _;
		let events = $node.node.get_and_clear_pending_events();
		let expected_payment_hash = $crate::ln::PaymentHash(
			bitcoin::hashes::sha256::Hash::hash(&$expected_payment_preimage.0).into_inner());
		if $expect_paths {
			assert!(events.len() > 1);
		} else {
			assert_eq!(events.len(), 1);
		}
		let expected_payment_id = match events[0] {
			$crate::util::events::Event::PaymentSent { ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat } => {
				assert_eq!($expected_payment_preimage, *payment_preimage);
				assert_eq!(expected_payment_hash, *payment_hash);
				assert!(fee_paid_msat.is_some());
				if $expected_fee_msat_opt.is_some() {
					assert_eq!(*fee_paid_msat, $expected_fee_msat_opt);
				}
				payment_id.unwrap()
			},
			_ => panic!("Unexpected event"),
		};
		if $expect_paths {
			for i in 1..events.len() {
				match events[i] {
					$crate::util::events::Event::PaymentPathSuccessful { payment_id, payment_hash, .. } => {
						assert_eq!(payment_id, expected_payment_id);
						assert_eq!(payment_hash, Some(expected_payment_hash));
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	} }
}

#[cfg(test)]
#[macro_export]
macro_rules! expect_payment_path_successful {
	($node: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			$crate::util::events::Event::PaymentPathSuccessful { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
}

macro_rules! expect_payment_forwarded {
	($node: expr, $prev_node: expr, $next_node: expr, $expected_fee: expr, $upstream_force_closed: expr, $downstream_force_closed: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentForwarded { fee_earned_msat, prev_channel_id, claim_from_onchain_tx, next_channel_id } => {
				assert_eq!(fee_earned_msat, $expected_fee);
				if fee_earned_msat.is_some() {
					// Is the event prev_channel_id in one of the channels between the two nodes?
					assert!($node.node.list_channels().iter().any(|x| x.counterparty.node_id == $prev_node.node.get_our_node_id() && x.channel_id == prev_channel_id.unwrap()));
				}
				// We check for force closures since a force closed channel is removed from the
				// node's channel list
				if !$downstream_force_closed {
					assert!($node.node.list_channels().iter().any(|x| x.counterparty.node_id == $next_node.node.get_our_node_id() && x.channel_id == next_channel_id.unwrap()));
				}
				assert_eq!(claim_from_onchain_tx, $upstream_force_closed);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

pub struct PaymentFailedConditions<'a> {
	pub(crate) expected_htlc_error_data: Option<(u16, &'a [u8])>,
	pub(crate) expected_blamed_scid: Option<u64>,
	pub(crate) expected_blamed_chan_closed: Option<bool>,
	pub(crate) expected_mpp_parts_remain: bool,
}

impl<'a> PaymentFailedConditions<'a> {
	pub fn new() -> Self {
		Self {
			expected_htlc_error_data: None,
			expected_blamed_scid: None,
			expected_blamed_chan_closed: None,
			expected_mpp_parts_remain: false,
		}
	}
	pub fn mpp_parts_remain(mut self) -> Self {
		self.expected_mpp_parts_remain = true;
		self
	}
	pub fn blamed_scid(mut self, scid: u64) -> Self {
		self.expected_blamed_scid = Some(scid);
		self
	}
	pub fn blamed_chan_closed(mut self, closed: bool) -> Self {
		self.expected_blamed_chan_closed = Some(closed);
		self
	}
	pub fn expected_htlc_error_data(mut self, code: u16, data: &'a [u8]) -> Self {
		self.expected_htlc_error_data = Some((code, data));
		self
	}
}

#[cfg(test)]
macro_rules! expect_payment_failed_with_update {
	($node: expr, $expected_payment_hash: expr, $rejected_by_dest: expr, $scid: expr, $chan_closed: expr) => {
		expect_payment_failed_conditions!($node, $expected_payment_hash, $rejected_by_dest,
			$crate::ln::functional_test_utils::PaymentFailedConditions::new().blamed_scid($scid).blamed_chan_closed($chan_closed));
	}
}

#[cfg(test)]
macro_rules! expect_payment_failed {
	($node: expr, $expected_payment_hash: expr, $rejected_by_dest: expr $(, $expected_error_code: expr, $expected_error_data: expr)*) => {
		#[allow(unused_mut)]
		let mut conditions = $crate::ln::functional_test_utils::PaymentFailedConditions::new();
		$(
			conditions = conditions.expected_htlc_error_data($expected_error_code, &$expected_error_data);
		)*
		expect_payment_failed_conditions!($node, $expected_payment_hash, $rejected_by_dest, conditions);
	};
}

#[cfg(test)]
macro_rules! expect_payment_failed_conditions {
	($node: expr, $expected_payment_hash: expr, $rejected_by_dest: expr, $conditions: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let expected_payment_id = match events[0] {
			Event::PaymentPathFailed { ref payment_hash, rejected_by_dest, ref error_code, ref error_data, ref path, ref retry, ref payment_id, ref network_update, .. } => {
				assert_eq!(*payment_hash, $expected_payment_hash, "unexpected payment_hash");
				assert_eq!(rejected_by_dest, $rejected_by_dest, "unexpected rejected_by_dest value");
				assert!(retry.is_some(), "expected retry.is_some()");
				assert_eq!(retry.as_ref().unwrap().final_value_msat, path.last().unwrap().fee_msat, "Retry amount should match last hop in path");
				assert_eq!(retry.as_ref().unwrap().payment_params.payee_pubkey, path.last().unwrap().pubkey, "Retry payee node_id should match last hop in path");

				assert!(error_code.is_some(), "expected error_code.is_some() = true");
				assert!(error_data.is_some(), "expected error_data.is_some() = true");
				if let Some((code, data)) = $conditions.expected_htlc_error_data {
					assert_eq!(error_code.unwrap(), code, "unexpected error code");
					assert_eq!(&error_data.as_ref().unwrap()[..], data, "unexpected error data");
				}

				if let Some(chan_closed) = $conditions.expected_blamed_chan_closed {
					match network_update {
						&Some($crate::routing::network_graph::NetworkUpdate::ChannelUpdateMessage { ref msg }) if !chan_closed => {
							if let Some(scid) = $conditions.expected_blamed_scid {
								assert_eq!(msg.contents.short_channel_id, scid);
							}
							assert_eq!(msg.contents.flags & 2, 0);
						},
						&Some($crate::routing::network_graph::NetworkUpdate::ChannelClosed { short_channel_id, is_permanent }) if chan_closed => {
							if let Some(scid) = $conditions.expected_blamed_scid {
								assert_eq!(short_channel_id, scid);
							}
							assert!(is_permanent);
						},
						Some(_) => panic!("Unexpected update type"),
						None => panic!("Expected update"),
					}
				}

				payment_id.unwrap()
			},
			_ => panic!("Unexpected event"),
		};
		if !$conditions.expected_mpp_parts_remain {
			$node.node.abandon_payment(expected_payment_id);
			let events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { ref payment_hash, ref payment_id } => {
					assert_eq!(*payment_hash, $expected_payment_hash, "unexpected second payment_hash");
					assert_eq!(*payment_id, expected_payment_id);
				}
				_ => panic!("Unexpected second event"),
			}
		}
	}
}

pub fn send_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_paths: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: PaymentSecret) -> PaymentId {
	let payment_id = origin_node.node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
	check_added_monitors!(origin_node, expected_paths.len());
	pass_along_route(origin_node, expected_paths, recv_value, our_payment_hash, our_payment_secret);
	payment_id
}

pub fn do_pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool, clear_recipient_events: bool, expected_preimage: Option<PaymentPreimage>) {
	let mut payment_event = SendEvent::from_event(ev);
	let mut prev_node = origin_node;

	for (idx, &node) in expected_path.iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(node);

		if idx == expected_path.len() - 1 && clear_recipient_events {
			let events_2 = node.node.get_and_clear_pending_events();
			if payment_received_expected {
				assert_eq!(events_2.len(), 1);
				match events_2[0] {
					Event::PaymentReceived { ref payment_hash, ref purpose, amount_msat } => {
						assert_eq!(our_payment_hash, *payment_hash);
						match &purpose {
							PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
								assert_eq!(expected_preimage, *payment_preimage);
								assert_eq!(our_payment_secret.unwrap(), *payment_secret);
							},
							PaymentPurpose::SpontaneousPayment(payment_preimage) => {
								assert_eq!(expected_preimage.unwrap(), *payment_preimage);
								assert!(our_payment_secret.is_none());
							},
						}
						assert_eq!(amount_msat, recv_value);
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				assert!(events_2.is_empty());
			}
		} else if idx != expected_path.len() - 1 {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors!(node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		}

		prev_node = node;
	}
}

pub fn pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool, expected_preimage: Option<PaymentPreimage>) {
	do_pass_along_path(origin_node, expected_path, recv_value, our_payment_hash, our_payment_secret, ev, payment_received_expected, true, expected_preimage);
}

pub fn pass_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: PaymentSecret) {
	let mut events = origin_node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_route.len());
	for (path_idx, (ev, expected_path)) in events.drain(..).zip(expected_route.iter()).enumerate() {
		// Once we've gotten through all the HTLCs, the last one should result in a
		// PaymentReceived (but each previous one should not!), .
		let expect_payment = path_idx == expected_route.len() - 1;
		pass_along_path(origin_node, expected_path, recv_value, our_payment_hash.clone(), Some(our_payment_secret), ev, expect_payment, None);
	}
}

pub fn send_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash, PaymentSecret, PaymentId) {
	let (our_payment_preimage, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(expected_route.last().unwrap());
	let payment_id = send_along_route_with_secret(origin_node, route, &[expected_route], recv_value, our_payment_hash, our_payment_secret);
	(our_payment_preimage, our_payment_hash, our_payment_secret, payment_id)
}

pub fn do_claim_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_preimage: PaymentPreimage) -> u64 {
	for path in expected_paths.iter() {
		assert_eq!(path.last().unwrap().node.get_our_node_id(), expected_paths[0].last().unwrap().node.get_our_node_id());
	}
	expected_paths[0].last().unwrap().node.claim_funds(our_payment_preimage);

	let claim_event = expected_paths[0].last().unwrap().node.get_and_clear_pending_events();
	assert_eq!(claim_event.len(), 1);
	match claim_event[0] {
		Event::PaymentClaimed { purpose: PaymentPurpose::SpontaneousPayment(preimage), .. }|
		Event::PaymentClaimed { purpose: PaymentPurpose::InvoicePayment { payment_preimage: Some(preimage), ..}, .. } =>
			assert_eq!(preimage, our_payment_preimage),
		Event::PaymentClaimed { purpose: PaymentPurpose::InvoicePayment { .. }, payment_hash, .. } =>
			assert_eq!(&payment_hash.0, &Sha256::hash(&our_payment_preimage.0)[..]),
		_ => panic!(),
	}

	check_added_monitors!(expected_paths[0].last().unwrap(), expected_paths.len());

	let mut expected_total_fee_msat = 0;

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
			($node: expr, $prev_node: expr, $next_node: expr, $new_msgs: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
					let fee = $node.node.channel_state.lock().unwrap().by_id.get(&next_msgs.as_ref().unwrap().0.channel_id).unwrap().config.forwarding_fee_base_msat;
					expect_payment_forwarded!($node, $next_node, $prev_node, Some(fee as u64), false, false);
					expected_total_fee_msat += fee as u64;
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
				// Since we are traversing in reverse, next_node is actually the previous node
				let next_node: &Node;
				if idx == expected_route.len() - 1 {
					next_node = origin_node;
				} else {
					next_node = expected_route[expected_route.len() - 1 - idx - 1];
				}
				mid_update_fulfill_dance!(node, prev_node, next_node, update_next_msgs);
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
		}
	}

	// Ensure that claim_funds is idempotent.
	expected_paths[0].last().unwrap().node.claim_funds(our_payment_preimage);
	assert!(expected_paths[0].last().unwrap().node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(expected_paths[0].last().unwrap(), 0);

	expected_total_fee_msat
}
pub fn claim_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_preimage: PaymentPreimage) {
	let expected_total_fee_msat = do_claim_payment_along_route(origin_node, expected_paths, skip_last, our_payment_preimage);
	if !skip_last {
		expect_payment_sent!(origin_node, our_payment_preimage, Some(expected_total_fee_msat));
	}
}

pub fn claim_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], our_payment_preimage: PaymentPreimage) {
	claim_payment_along_route(origin_node, &[expected_route], false, our_payment_preimage);
}

pub const TEST_FINAL_CLTV: u32 = 70;

pub fn route_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash, PaymentSecret) {
	let payment_params = PaymentParameters::from_node_id(expected_route.last().unwrap().node.get_our_node_id())
		.with_features(InvoiceFeatures::known());
	let route = get_route!(origin_node, payment_params, recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.paths.len(), 1);
	assert_eq!(route.paths[0].len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	let res = send_along_route(origin_node, route, expected_route, recv_value);
	(res.0, res.1, res.2)
}

pub fn route_over_limit<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64)  {
	let payment_params = PaymentParameters::from_node_id(expected_route.last().unwrap().node.get_our_node_id())
		.with_features(InvoiceFeatures::known());
	let network_graph = origin_node.network_graph.read_only();
	let scorer = test_utils::TestScorer::with_penalty(0);
	let seed = [0u8; 32];
	let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();
	let route = get_route(
		&origin_node.node.get_our_node_id(), &payment_params, &network_graph,
		None, recv_value, TEST_FINAL_CLTV, origin_node.logger, &scorer, &random_seed_bytes).unwrap();
	assert_eq!(route.paths.len(), 1);
	assert_eq!(route.paths[0].len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	let (_, our_payment_hash, our_payment_preimage) = get_payment_preimage_hash!(expected_route.last().unwrap());
	unwrap_send_err!(origin_node.node.send_payment(&route, our_payment_hash, &Some(our_payment_preimage)), true, APIError::ChannelUnavailable { ref err },
		assert!(err.contains("Cannot send value that would put us over the max HTLC value in flight our peer will accept")));
}

pub fn send_payment<'a, 'b, 'c>(origin: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64)  {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage);
}

pub fn fail_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_hash: PaymentHash) {
	for path in expected_paths.iter() {
		assert_eq!(path.last().unwrap().node.get_our_node_id(), expected_paths[0].last().unwrap().node.get_our_node_id());
	}
	expected_paths[0].last().unwrap().node.fail_htlc_backwards(&our_payment_hash);
	expect_pending_htlcs_forwardable!(expected_paths[0].last().unwrap());

	pass_failed_payment_back(origin_node, expected_paths, skip_last, our_payment_hash);
}

pub fn pass_failed_payment_back<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths_slice: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_hash: PaymentHash) {
	let mut expected_paths: Vec<_> = expected_paths_slice.iter().collect();
	check_added_monitors!(expected_paths[0].last().unwrap(), expected_paths.len());

	let mut per_path_msgs: Vec<((msgs::UpdateFailHTLC, msgs::CommitmentSigned), PublicKey)> = Vec::with_capacity(expected_paths.len());
	let events = expected_paths[0].last().unwrap().node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());
	for ev in events.iter() {
		let (update_fail, commitment_signed, node_id) = match ev {
			&MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert_eq!(update_fail_htlcs.len(), 1);
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				(update_fail_htlcs[0].clone(), commitment_signed.clone(), node_id.clone())
			},
			_ => panic!("Unexpected event"),
		};
		per_path_msgs.push(((update_fail, commitment_signed), node_id));
	}
	per_path_msgs.sort_unstable_by(|(_, node_id_a), (_, node_id_b)| node_id_a.cmp(node_id_b));
	expected_paths.sort_unstable_by(|path_a, path_b| path_a[path_a.len() - 2].node.get_our_node_id().cmp(&path_b[path_b.len() - 2].node.get_our_node_id()));

	for (i, (expected_route, (path_msgs, next_hop))) in expected_paths.iter().zip(per_path_msgs.drain(..)).enumerate() {
		let mut next_msgs = Some(path_msgs);
		let mut expected_next_node = next_hop;
		let mut prev_node = expected_route.last().unwrap();

		for (idx, node) in expected_route.iter().rev().enumerate().skip(1) {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			let update_next_node = !skip_last || idx != expected_route.len() - 1;
			if next_msgs.is_some() {
				node.node.handle_update_fail_htlc(&prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
				commitment_signed_dance!(node, prev_node, next_msgs.as_ref().unwrap().1, update_next_node);
				if !update_next_node {
					expect_pending_htlcs_forwardable!(node);
				}
			}
			let events = node.node.get_and_clear_pending_msg_events();
			if update_next_node {
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
			let prev_node = expected_route.first().unwrap();
			origin_node.node.handle_update_fail_htlc(&prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
			check_added_monitors!(origin_node, 0);
			assert!(origin_node.node.get_and_clear_pending_msg_events().is_empty());
			commitment_signed_dance!(origin_node, prev_node, next_msgs.as_ref().unwrap().1, false);
			let events = origin_node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let expected_payment_id = match events[0] {
				Event::PaymentPathFailed { payment_hash, rejected_by_dest, all_paths_failed, ref path, ref payment_id, .. } => {
					assert_eq!(payment_hash, our_payment_hash);
					assert!(rejected_by_dest);
					assert_eq!(all_paths_failed, i == expected_paths.len() - 1);
					for (idx, hop) in expected_route.iter().enumerate() {
						assert_eq!(hop.node.get_our_node_id(), path[idx].pubkey);
					}
					payment_id.unwrap()
				},
				_ => panic!("Unexpected event"),
			};
			if i == expected_paths.len() - 1 {
				origin_node.node.abandon_payment(expected_payment_id);
				let events = origin_node.node.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					Event::PaymentFailed { ref payment_hash, ref payment_id } => {
						assert_eq!(*payment_hash, our_payment_hash, "unexpected second payment_hash");
						assert_eq!(*payment_id, expected_payment_id);
					}
					_ => panic!("Unexpected second event"),
				}
			}
		}
	}

	// Ensure that fail_htlc_backwards is idempotent.
	expected_paths[0].last().unwrap().node.fail_htlc_backwards(&our_payment_hash);
	assert!(expected_paths[0].last().unwrap().node.get_and_clear_pending_events().is_empty());
	assert!(expected_paths[0].last().unwrap().node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(expected_paths[0].last().unwrap(), 0);
}

pub fn fail_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], our_payment_hash: PaymentHash)  {
	fail_payment_along_route(origin_node, &[&expected_path[..]], false, our_payment_hash);
}

pub fn create_chanmon_cfgs(node_count: usize) -> Vec<TestChanMonCfg> {
	let mut chan_mon_cfgs = Vec::new();
	for i in 0..node_count {
		let tx_broadcaster = test_utils::TestBroadcaster {
			txn_broadcasted: Mutex::new(Vec::new()),
			blocks: Arc::new(Mutex::new(vec![(genesis_block(Network::Testnet), 0)])),
		};
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };
		let chain_source = test_utils::TestChainSource::new(Network::Testnet);
		let logger = test_utils::TestLogger::with_id(format!("node {}", i));
		let persister = test_utils::TestPersister::new();
		let seed = [i as u8; 32];
		let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
		let network_graph = NetworkGraph::new(chain_source.genesis_hash);

		chan_mon_cfgs.push(TestChanMonCfg{ tx_broadcaster, fee_estimator, chain_source, logger, persister, keys_manager, network_graph });
	}

	chan_mon_cfgs
}

pub fn create_node_cfgs<'a>(node_count: usize, chanmon_cfgs: &'a Vec<TestChanMonCfg>) -> Vec<NodeCfg<'a>> {
	let mut nodes = Vec::new();

	for i in 0..node_count {
		let chain_monitor = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[i].chain_source), &chanmon_cfgs[i].tx_broadcaster, &chanmon_cfgs[i].logger, &chanmon_cfgs[i].fee_estimator, &chanmon_cfgs[i].persister, &chanmon_cfgs[i].keys_manager);
		let seed = [i as u8; 32];
		nodes.push(NodeCfg {
			chain_source: &chanmon_cfgs[i].chain_source,
			logger: &chanmon_cfgs[i].logger,
			tx_broadcaster: &chanmon_cfgs[i].tx_broadcaster,
			fee_estimator: &chanmon_cfgs[i].fee_estimator,
			chain_monitor,
			keys_manager: &chanmon_cfgs[i].keys_manager,
			node_seed: seed,
			features: InitFeatures::known(),
			network_graph: &chanmon_cfgs[i].network_graph,
		});
	}

	nodes
}

pub fn test_default_channel_config() -> UserConfig {
	let mut default_config = UserConfig::default();
	// Set cltv_expiry_delta slightly lower to keep the final CLTV values inside one byte in our
	// tests so that our script-length checks don't fail (see ACCEPTED_HTLC_SCRIPT_WEIGHT).
	default_config.channel_options.cltv_expiry_delta = MIN_CLTV_EXPIRY_DELTA;
	default_config.channel_options.announced_channel = true;
	default_config.peer_channel_config_limits.force_announced_channel_preference = false;
	// When most of our tests were written, the default HTLC minimum was fixed at 1000.
	// It now defaults to 1, so we simply set it to the expected value here.
	default_config.own_channel_config.our_htlc_minimum_msat = 1000;
	// When most of our tests were written, we didn't have the notion of a `max_dust_htlc_exposure_msat`,
	// It now defaults to 5_000_000 msat; to avoid interfering with tests we bump it to 50_000_000 msat.
	default_config.channel_options.max_dust_htlc_exposure_msat = 50_000_000;
	default_config
}

pub fn create_node_chanmgrs<'a, 'b>(node_count: usize, cfgs: &'a Vec<NodeCfg<'b>>, node_config: &[Option<UserConfig>]) -> Vec<ChannelManager<EnforcingSigner, &'a TestChainMonitor<'b>, &'b test_utils::TestBroadcaster, &'a test_utils::TestKeysInterface, &'b test_utils::TestFeeEstimator, &'b test_utils::TestLogger>> {
	let mut chanmgrs = Vec::new();
	for i in 0..node_count {
		let network = Network::Testnet;
		let params = ChainParameters {
			network,
			best_block: BestBlock::from_genesis(network),
		};
		let node = ChannelManager::new(cfgs[i].fee_estimator, &cfgs[i].chain_monitor, cfgs[i].tx_broadcaster, cfgs[i].logger, cfgs[i].keys_manager,
			if node_config[i].is_some() { node_config[i].clone().unwrap() } else { test_default_channel_config() }, params);
		chanmgrs.push(node);
	}

	chanmgrs
}

pub fn create_network<'a, 'b: 'a, 'c: 'b>(node_count: usize, cfgs: &'b Vec<NodeCfg<'c>>, chan_mgrs: &'a Vec<ChannelManager<EnforcingSigner, &'b TestChainMonitor<'c>, &'c test_utils::TestBroadcaster, &'b test_utils::TestKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>>) -> Vec<Node<'a, 'b, 'c>> {
	let mut nodes = Vec::new();
	let chan_count = Rc::new(RefCell::new(0));
	let payment_count = Rc::new(RefCell::new(0));
	let connect_style = Rc::new(RefCell::new(ConnectStyle::random_style()));

	for i in 0..node_count {
		let net_graph_msg_handler = NetGraphMsgHandler::new(cfgs[i].network_graph, None, cfgs[i].logger);
		nodes.push(Node{
			chain_source: cfgs[i].chain_source, tx_broadcaster: cfgs[i].tx_broadcaster,
			chain_monitor: &cfgs[i].chain_monitor, keys_manager: &cfgs[i].keys_manager,
			node: &chan_mgrs[i], network_graph: &cfgs[i].network_graph, net_graph_msg_handler,
			node_seed: cfgs[i].node_seed, network_chan_count: chan_count.clone(),
			network_payment_count: payment_count.clone(), logger: cfgs[i].logger,
			blocks: Arc::clone(&cfgs[i].tx_broadcaster.blocks),
			connect_style: Rc::clone(&connect_style),
		})
	}

	for i in 0..node_count {
		for j in (i+1)..node_count {
			nodes[i].node.peer_connected(&nodes[j].node.get_our_node_id(), &msgs::Init { features: cfgs[j].features.clone(), remote_network_address: None });
			nodes[j].node.peer_connected(&nodes[i].node.get_our_node_id(), &msgs::Init { features: cfgs[i].features.clone(), remote_network_address: None });
		}
	}

	nodes
}

// Note that the following only works for CLTV values up to 128
pub const ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 137; //Here we have a diff due to HTLC CLTV expiry being < 2^15 in test
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
			let mut iter = node_txn[0].input[0].witness.iter();
			iter.next().expect("expected 3 witness items");
			iter.next().expect("expected 3 witness items");
			assert!(iter.next().expect("expected 3 witness items").len() > 106); // must spend an htlc output
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

pub fn handle_announce_close_broadcast_events<'a, 'b, 'c>(nodes: &Vec<Node<'a, 'b, 'c>>, a: usize, b: usize, needs_err_handle: bool, expected_error: &str)  {
	let events_1 = nodes[a].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 2);
	let as_update = match events_1[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};
	match events_1[1] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[b].node.get_our_node_id());
			assert_eq!(msg.data, expected_error);
			if needs_err_handle {
				nodes[b].node.handle_error(&nodes[a].node.get_our_node_id(), msg);
			}
		},
		_ => panic!("Unexpected event"),
	}

	let events_2 = nodes[b].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), if needs_err_handle { 1 } else { 2 });
	let bs_update = match events_2[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};
	if !needs_err_handle {
		match events_2[1] {
			MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
				assert_eq!(node_id, nodes[a].node.get_our_node_id());
				assert_eq!(msg.data, expected_error);
			},
			_ => panic!("Unexpected event"),
		}
	}

	for node in nodes {
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}
}

pub fn get_announce_close_broadcast_events<'a, 'b, 'c>(nodes: &Vec<Node<'a, 'b, 'c>>, a: usize, b: usize)  {
	handle_announce_close_broadcast_events(nodes, a, b, false, "Channel closed because commitment or closing transaction was confirmed on chain.");
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
			let channel_ready = if let Some(&MessageSendEvent::SendChannelReady { ref node_id, ref msg }) = msg_events.get(0) {
				idx += 1;
				assert_eq!(*node_id, $dst_node.node.get_our_node_id());
				Some(msg.clone())
			} else {
				None
			};

			if let Some(&MessageSendEvent::SendAnnouncementSignatures { ref node_id, msg: _ }) = msg_events.get(idx) {
				idx += 1;
				assert_eq!(*node_id, $dst_node.node.get_our_node_id());
			}

			let mut revoke_and_ack = None;
			let mut commitment_update = None;
			let order = if let Some(ev) = msg_events.get(idx) {
				match ev {
					&MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						revoke_and_ack = Some(msg.clone());
						idx += 1;
						RAACommitmentOrder::RevokeAndACKFirst
					},
					&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						commitment_update = Some(updates.clone());
						idx += 1;
						RAACommitmentOrder::CommitmentFirst
					},
					_ => RAACommitmentOrder::CommitmentFirst,
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
						idx += 1;
					},
					&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						assert!(commitment_update.is_none());
						commitment_update = Some(updates.clone());
						idx += 1;
					},
					_ => {},
				}
			}

			if let Some(&MessageSendEvent::SendChannelUpdate { ref node_id, ref msg }) = msg_events.get(idx) {
				assert_eq!(*node_id, $dst_node.node.get_our_node_id());
				idx += 1;
				assert_eq!(msg.contents.flags & 2, 0); // "disabled" flag must not be set as we just reconnected.
			}

			assert_eq!(msg_events.len(), idx);

			(channel_ready, revoke_and_ack, commitment_update, order)
		}
	}
}

/// pending_htlc_adds includes both the holding cell and in-flight update_add_htlcs, whereas
/// for claims/fails they are separated out.
pub fn reconnect_nodes<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, send_channel_ready: (bool, bool), pending_htlc_adds: (i64, i64), pending_htlc_claims: (usize, usize), pending_htlc_fails: (usize, usize), pending_cell_htlc_claims: (usize, usize), pending_cell_htlc_fails: (usize, usize), pending_raa: (bool, bool))  {
	node_a.node.peer_connected(&node_b.node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty(), remote_network_address: None });
	let reestablish_1 = get_chan_reestablish_msgs!(node_a, node_b);
	node_b.node.peer_connected(&node_a.node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty(), remote_network_address: None });
	let reestablish_2 = get_chan_reestablish_msgs!(node_b, node_a);

	if send_channel_ready.0 {
		// If a expects a channel_ready, it better not think it has received a revoke_and_ack
		// from b
		for reestablish in reestablish_1.iter() {
			assert_eq!(reestablish.next_remote_commitment_number, 0);
		}
	}
	if send_channel_ready.1 {
		// If b expects a channel_ready, it better not think it has received a revoke_and_ack
		// from a
		for reestablish in reestablish_2.iter() {
			assert_eq!(reestablish.next_remote_commitment_number, 0);
		}
	}
	if send_channel_ready.0 || send_channel_ready.1 {
		// If we expect any channel_ready's, both sides better have set
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
	assert!((pending_htlc_adds.0 == 0 && pending_htlc_claims.0 == 0 && pending_htlc_fails.0 == 0 &&
			 pending_cell_htlc_claims.0 == 0 && pending_cell_htlc_fails.0 == 0) ||
			(pending_htlc_adds.1 == 0 && pending_htlc_claims.1 == 0 && pending_htlc_fails.1 == 0 &&
			 pending_cell_htlc_claims.1 == 0 && pending_cell_htlc_fails.1 == 0));

	for chan_msgs in resp_1.drain(..) {
		if send_channel_ready.0 {
			node_a.node.handle_channel_ready(&node_b.node.get_our_node_id(), &chan_msgs.0.unwrap());
			let announcement_event = node_a.node.get_and_clear_pending_msg_events();
			if !announcement_event.is_empty() {
				assert_eq!(announcement_event.len(), 1);
				if let MessageSendEvent::SendChannelUpdate { .. } = announcement_event[0] {
					//TODO: Test announcement_sigs re-sending
				} else { panic!("Unexpected event! {:?}", announcement_event[0]); }
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
		if pending_htlc_adds.0 != 0 || pending_htlc_claims.0 != 0 || pending_htlc_fails.0 != 0 || pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
			let commitment_update = chan_msgs.2.unwrap();
			if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
				assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.0 as usize);
			} else {
				assert!(commitment_update.update_add_htlcs.is_empty());
			}
			assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.0 + pending_cell_htlc_claims.0);
			assert_eq!(commitment_update.update_fail_htlcs.len(), pending_htlc_fails.0 + pending_cell_htlc_fails.0);
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
		if send_channel_ready.1 {
			node_b.node.handle_channel_ready(&node_a.node.get_our_node_id(), &chan_msgs.0.unwrap());
			let announcement_event = node_b.node.get_and_clear_pending_msg_events();
			if !announcement_event.is_empty() {
				assert_eq!(announcement_event.len(), 1);
				match announcement_event[0] {
					MessageSendEvent::SendChannelUpdate { .. } => {},
					MessageSendEvent::SendAnnouncementSignatures { .. } => {},
					_ => panic!("Unexpected event {:?}!", announcement_event[0]),
				}
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
		if pending_htlc_adds.1 != 0 || pending_htlc_claims.1 != 0 || pending_htlc_fails.1 != 0 || pending_cell_htlc_claims.1 != 0 || pending_cell_htlc_fails.1 != 0 {
			let commitment_update = chan_msgs.2.unwrap();
			if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
				assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.1 as usize);
			}
			assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.1 + pending_cell_htlc_claims.1);
			assert_eq!(commitment_update.update_fail_htlcs.len(), pending_htlc_fails.1 + pending_cell_htlc_fails.1);
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
