// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The top-level network map tracking logic lives here.

use bitcoin::secp256k1::key::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::blockdata::opcodes;
use bitcoin::hash_types::BlockHash;

use chain;
use chain::Access;
use ln::features::{ChannelFeatures, NodeFeatures};
use ln::msgs::{DecodeError, ErrorAction, LightningError, RoutingMessageHandler, NetAddress, MAX_VALUE_MSAT};
use ln::msgs::{ChannelAnnouncement, ChannelUpdate, NodeAnnouncement, OptionalField};
use ln::msgs::{QueryChannelRange, ReplyChannelRange, QueryShortChannelIds, ReplyShortChannelIdsEnd};
use ln::msgs;
use util::ser::{Writeable, Readable, Writer};
use util::logger::Logger;
use util::events;

use std::{cmp, fmt};
use std::sync::{RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry as BtreeEntry;
use std::collections::HashMap;
use std::ops::Deref;
use bitcoin::hashes::hex::ToHex;

/// Maximum number of short_channel_id values that can be encoded in a
/// single reply_channel_range or query_short_channel_ids messages when
/// using raw encoding. The maximum value ensures that the 8-byte SCIDs
/// fit inside the maximum size of the Lightning message, 65535-bytes.
const MAX_SHORT_CHANNEL_ID_BATCH_SIZE: usize = 8000;

/// Maximum number of reply_channel_range messages we will allow in
/// reply to a query_channel_range. This value creates an upper-limit 
/// on the number of SCIDs we process in reply to a single query.
const MAX_REPLY_CHANNEL_RANGE_PER_QUERY: usize = 250;

/// Represents the network as nodes and channels between them
#[derive(PartialEq)]
pub struct NetworkGraph {
	genesis_hash: BlockHash,
	channels: BTreeMap<u64, ChannelInfo>,
	nodes: BTreeMap<PublicKey, NodeInfo>,
}

/// A simple newtype for RwLockReadGuard<'a, NetworkGraph>.
/// This exists only to make accessing a RwLock<NetworkGraph> possible from
/// the C bindings, as it can be done directly in Rust code.
pub struct LockedNetworkGraph<'a>(pub RwLockReadGuard<'a, NetworkGraph>);

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
pub struct NetGraphMsgHandler<C: Deref, L: Deref> where C::Target: chain::Access, L::Target: Logger {
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	/// Representation of the payment channel network
	pub network_graph: RwLock<NetworkGraph>,
	chain_access: Option<C>,
	full_syncs_requested: AtomicUsize,
	pending_events: Mutex<Vec<events::MessageSendEvent>>,
	chan_range_query_tasks: Mutex<HashMap<PublicKey, ChanRangeQueryTask>>,
	scid_query_tasks: Mutex<HashMap<PublicKey, ScidQueryTask>>,
	logger: L,
}

impl<C: Deref, L: Deref> NetGraphMsgHandler<C, L> where C::Target: chain::Access, L::Target: Logger {
	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming a fresh network graph.
	/// Chain monitor is used to make sure announced channels exist on-chain,
	/// channel data is correct, and that the announcement is signed with
	/// channel owners' keys.
	pub fn new(genesis_hash: BlockHash, chain_access: Option<C>, logger: L) -> Self {
		NetGraphMsgHandler {
			secp_ctx: Secp256k1::verification_only(),
			network_graph: RwLock::new(NetworkGraph::new(genesis_hash)),
			full_syncs_requested: AtomicUsize::new(0),
			chain_access,
			pending_events: Mutex::new(vec![]),
			chan_range_query_tasks: Mutex::new(HashMap::new()),
			scid_query_tasks: Mutex::new(HashMap::new()),
			logger,
		}
	}

	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming an existing Network Graph.
	pub fn from_net_graph(chain_access: Option<C>, logger: L, network_graph: NetworkGraph) -> Self {
		NetGraphMsgHandler {
			secp_ctx: Secp256k1::verification_only(),
			network_graph: RwLock::new(network_graph),
			full_syncs_requested: AtomicUsize::new(0),
			chain_access,
			pending_events: Mutex::new(vec![]),
			chan_range_query_tasks: Mutex::new(HashMap::new()),
			scid_query_tasks: Mutex::new(HashMap::new()),
			logger,
		}
	}

	/// Take a read lock on the network_graph and return it in the C-bindings
	/// newtype helper. This is likely only useful when called via the C
	/// bindings as you can call `self.network_graph.read().unwrap()` in Rust
	/// yourself.
	pub fn read_locked_graph<'a>(&'a self) -> LockedNetworkGraph<'a> {
		LockedNetworkGraph(self.network_graph.read().unwrap())
	}

	/// Enqueues a message send event for a batch of short_channel_ids
	/// in a task.
	fn finalize_query_short_ids(&self, task: &mut ScidQueryTask) {
		let scid_size = std::cmp::min(task.short_channel_ids.len(), MAX_SHORT_CHANNEL_ID_BATCH_SIZE);
		let mut short_channel_ids: Vec<u64> = Vec::with_capacity(scid_size);
		for scid in task.short_channel_ids.drain(..scid_size) {
			short_channel_ids.push(scid);
		}

		log_debug!(self.logger, "Sending query_short_channel_ids peer={}, batch_size={}", log_pubkey!(task.node_id), scid_size);

		// enqueue the message to the peer
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::MessageSendEvent::SendShortIdsQuery {
			node_id: task.node_id.clone(),
			msg: QueryShortChannelIds {
				chain_hash: task.chain_hash.clone(),
				short_channel_ids,
			}
		});
	}
}

impl<'a> LockedNetworkGraph<'a> {
	/// Get a reference to the NetworkGraph which this read-lock contains.
	pub fn graph(&self) -> &NetworkGraph {
		&*self.0
	}
}


macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr ) => {
		match $secp_ctx.verify($msg, $sig, $pubkey) {
			Ok(_) => {},
			Err(_) => return Err(LightningError{err: "Invalid signature from remote node".to_owned(), action: ErrorAction::IgnoreError}),
		}
	};
}

impl<C: Deref + Sync + Send, L: Deref + Sync + Send> RoutingMessageHandler for NetGraphMsgHandler<C, L> where C::Target: chain::Access, L::Target: Logger {
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.write().unwrap().update_node_from_announcement(msg, &self.secp_ctx)?;
		Ok(msg.contents.excess_data.is_empty() && msg.contents.excess_address_data.is_empty())
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.write().unwrap().update_channel_from_announcement(msg, &self.chain_access, &self.secp_ctx)?;
		log_trace!(self.logger, "Added channel_announcement for {}{}", msg.contents.short_channel_id, if !msg.contents.excess_data.is_empty() { " with excess uninterpreted data!" } else { "" });
		Ok(msg.contents.excess_data.is_empty())
	}

	fn handle_htlc_fail_channel_update(&self, update: &msgs::HTLCFailChannelUpdate) {
		match update {
			&msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg } => {
				let _ = self.network_graph.write().unwrap().update_channel(msg, &self.secp_ctx);
			},
			&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id, is_permanent } => {
				self.network_graph.write().unwrap().close_channel_from_update(short_channel_id, is_permanent);
			},
			&msgs::HTLCFailChannelUpdate::NodeFailure { ref node_id, is_permanent } => {
				self.network_graph.write().unwrap().fail_node(node_id, is_permanent);
			},
		}
	}

	fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
		self.network_graph.write().unwrap().update_channel(msg, &self.secp_ctx)?;
		Ok(msg.contents.excess_data.is_empty())
	}

	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)> {
		let network_graph = self.network_graph.read().unwrap();
		let mut result = Vec::with_capacity(batch_amount as usize);
		let mut iter = network_graph.get_channels().range(starting_point..);
		while result.len() < batch_amount as usize {
			if let Some((_, ref chan)) = iter.next() {
				if chan.announcement_message.is_some() {
					let chan_announcement = chan.announcement_message.clone().unwrap();
					let mut one_to_two_announcement: Option<msgs::ChannelUpdate> = None;
					let mut two_to_one_announcement: Option<msgs::ChannelUpdate> = None;
					if let Some(one_to_two) = chan.one_to_two.as_ref() {
						one_to_two_announcement = one_to_two.last_update_message.clone();
					}
					if let Some(two_to_one) = chan.two_to_one.as_ref() {
						two_to_one_announcement = two_to_one.last_update_message.clone();
					}
					result.push((chan_announcement, one_to_two_announcement, two_to_one_announcement));
				} else {
					// TODO: We may end up sending un-announced channel_updates if we are sending
					// initial sync data while receiving announce/updates for this channel.
				}
			} else {
				return result;
			}
		}
		result
	}

	fn get_next_node_announcements(&self, starting_point: Option<&PublicKey>, batch_amount: u8) -> Vec<NodeAnnouncement> {
		let network_graph = self.network_graph.read().unwrap();
		let mut result = Vec::with_capacity(batch_amount as usize);
		let mut iter = if let Some(pubkey) = starting_point {
				let mut iter = network_graph.get_nodes().range((*pubkey)..);
				iter.next();
				iter
			} else {
				network_graph.get_nodes().range(..)
			};
		while result.len() < batch_amount as usize {
			if let Some((_, ref node)) = iter.next() {
				if let Some(node_info) = node.announcement_info.as_ref() {
					if node_info.announcement_message.is_some() {
						result.push(node_info.announcement_message.clone().unwrap());
					}
				}
			} else {
				return result;
			}
		}
		result
	}

	fn should_request_full_sync(&self, _node_id: &PublicKey) -> bool {
		//TODO: Determine whether to request a full sync based on the network map.
		const FULL_SYNCS_TO_REQUEST: usize = 5;
		if self.full_syncs_requested.load(Ordering::Acquire) < FULL_SYNCS_TO_REQUEST {
			self.full_syncs_requested.fetch_add(1, Ordering::AcqRel);
			true
		} else {
			false
		}
	}

	fn query_channel_range(&self, their_node_id: &PublicKey, chain_hash: BlockHash, first_blocknum: u32, number_of_blocks: u32) -> Result<(), LightningError> {
		// We must ensure that we only have a single in-flight query
		// to the remote peer. If we already have a query, then we fail
		let mut query_range_tasks_lock = self.chan_range_query_tasks.lock().unwrap();
		let query_range_tasks = &mut *query_range_tasks_lock;
		if query_range_tasks.contains_key(their_node_id) {
			return Err(LightningError {
				err: String::from("query_channel_range already in-flight"),
				action: ErrorAction::IgnoreError,
			});
		}

		// Construct a new task to keep track of the query until the full
		// range query has been completed
		let task = ChanRangeQueryTask::new(their_node_id, chain_hash, first_blocknum, number_of_blocks);
		query_range_tasks.insert(their_node_id.clone(), task);

		// Enqueue the message send event
		log_debug!(self.logger, "Sending query_channel_range peer={}, first_blocknum={}, number_of_blocks={}", log_pubkey!(their_node_id), first_blocknum, number_of_blocks);
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::MessageSendEvent::SendChannelRangeQuery {
			node_id: their_node_id.clone(),
			msg: QueryChannelRange {
				chain_hash,
				first_blocknum,
				number_of_blocks,
			},
		});
		Ok(())
	}

	/// A query should only request channels referring to unspent outputs.
	/// This method does not validate this requirement and expects the
	/// caller to ensure SCIDs are unspent.
	fn query_short_channel_ids(&self, their_node_id: &PublicKey, chain_hash: BlockHash, short_channel_ids: Vec<u64>) -> Result<(), LightningError> {
		// Create a new task or add to the existing task
		let mut query_scids_tasks_lock = self.scid_query_tasks.lock().unwrap();
		let query_scids_tasks = &mut *query_scids_tasks_lock;

		// For an existing task we append the short_channel_ids which will be sent when the
		// current in-flight batch completes.
		if let Some(task) = query_scids_tasks.get_mut(their_node_id) {
			task.add(short_channel_ids);
			return Ok(());
		}

		// For a new task we create the task with short_channel_ids and send the first
		// batch immediately.
		query_scids_tasks.insert(their_node_id.clone(), ScidQueryTask::new(
			their_node_id,
			chain_hash.clone(),
			short_channel_ids,
		));
		let task = query_scids_tasks.get_mut(their_node_id).unwrap();
		self.finalize_query_short_ids(task);
		return Ok(());
	}

	fn handle_reply_channel_range(&self, their_node_id: &PublicKey, msg: &ReplyChannelRange) -> Result<(), LightningError> {
		log_debug!(self.logger, "Handling reply_channel_range peer={}, first_blocknum={}, number_of_blocks={}, full_information={}, scids={}", log_pubkey!(their_node_id), msg.first_blocknum, msg.number_of_blocks, msg.full_information, msg.short_channel_ids.len(),);

		// First we obtain a lock on the task hashmap. In order to avoid borrowing issues
		// we will access the task as needed.
		let mut query_range_tasks = self.chan_range_query_tasks.lock().unwrap();

		// If there is no currently executing task then we have received
		// an invalid message and will return an error
		if query_range_tasks.get(their_node_id).is_none() {
			return Err(LightningError {
				err: String::from("Received unknown reply_channel_range message"),
				action: ErrorAction::IgnoreError,
			});
		}

		// Now that we know we have a task, we can extract a few values for use
		// in validations without having to access the task repeatedly
		let (task_chain_hash, task_first_blocknum, task_number_of_blocks, task_received_first_block, task_received_last_block, task_number_of_replies) = {
			let task = query_range_tasks.get(their_node_id).unwrap();
			(task.chain_hash, task.first_blocknum, task.number_of_blocks, task.received_first_block, task.received_last_block, task.number_of_replies)
		};

		// Validate the chain_hash matches the chain_hash we used in the query.
		// If it does not, then the message is malformed and we return an error
		if msg.chain_hash != task_chain_hash {
			query_range_tasks.remove(their_node_id);
			return Err(LightningError {
				err: String::from("Received reply_channel_range with invalid chain_hash"),
				action: ErrorAction::IgnoreError,
			});
		}

		// Validate that the remote node maintains up-to-date channel
		// information for chain_hash. Some nodes use the full_information
		// flag to indicate multi-part messages so we must check whether
		// we received information as well.
		if !msg.full_information && msg.short_channel_ids.len() == 0 {
			query_range_tasks.remove(their_node_id);
			return Err(LightningError {
				err: String::from("Received reply_channel_range with no information available"),
				action: ErrorAction::IgnoreError,
			});
		}

		// Calculate the last block for the message and the task
		let msg_last_block = last_blocknum(msg.first_blocknum, msg.number_of_blocks);
		let task_last_block = last_blocknum(task_first_blocknum, task_number_of_blocks);

		// On the first message...
		if task_received_first_block.is_none() {
			// The replies can be a superset of the queried block range, but the
			// replies must include our requested query range. We check if the
			// start of the replies is greater than the start of our query. If
			// so, the start of our query is excluded and the message is malformed.
			if msg.first_blocknum > task_first_blocknum {
				query_range_tasks.remove(their_node_id);
				return Err(LightningError {
					err: String::from("Failing reply_channel_range with invalid first_blocknum"),
					action: ErrorAction::IgnoreError,
				});
			}

			// Next, we ensure the reply has at least some information matching
			// our query. If the received last_blocknum is less than our query's
			// first_blocknum then the reply does not encompass the query range
			// and the message is malformed.
			if msg_last_block < task_first_blocknum {
				query_range_tasks.remove(their_node_id);
				return Err(LightningError {
					err: String::from("Failing reply_channel_range with non-overlapping first reply"),
					action: ErrorAction::IgnoreError,
				});
			}

			// Capture the first block and last block so that subsequent messages
			// can be validated.
			let task = query_range_tasks.get_mut(their_node_id).unwrap();
			task.received_first_block = Some(msg.first_blocknum);
			task.received_last_block = Some(msg_last_block);
		}
		// On subsequent message(s)...
		else {
			// We need to validate the sequence of the reply message is expected.
			// Subsequent messages must set the first_blocknum to the previous
			// message's first_blocknum plus number_of_blocks. There is discrepancy
			// in implementation where some resume on the last sent block. We will
			// loosen the restriction and accept either, and otherwise consider the
			// message malformed and return an error.
			let task_received_last_block = task_received_last_block.unwrap();
			if msg.first_blocknum != task_received_last_block && msg.first_blocknum != task_received_last_block + 1 {
				query_range_tasks.remove(their_node_id);
				return Err(LightningError {
					err: String::from("Failing reply_channel_range with invalid sequence"),
					action: ErrorAction::IgnoreError,
				});
			}

			// Next we check to see that we have received a realistic number of
			// reply messages for a query. This caps the allocation exposure
			// for short_channel_ids that will be batched and sent in query channels.
			if task_number_of_replies + 1 > MAX_REPLY_CHANNEL_RANGE_PER_QUERY {
				query_range_tasks.remove(their_node_id);
				return Err(LightningError {
					err: String::from("Failing reply_channel_range due to excessive messages"),
					action: ErrorAction::IgnoreError,
				});
			}

			// Capture the last_block in our task so that subsequent messages
			// can be validated.
			let task = query_range_tasks.get_mut(their_node_id).unwrap();
			task.number_of_replies += 1;
			task.received_last_block = Some(msg_last_block);
		}

		// We filter the short_channel_ids to those inside the query range.
		// The most significant 3-bytes of the short_channel_id are the block.
		{
			let mut filtered_short_channel_ids: Vec<u64> = msg.short_channel_ids.clone().into_iter().filter(|short_channel_id| {
				let block = short_channel_id >> 40;
				return block >= query_range_tasks.get(their_node_id).unwrap().first_blocknum as u64 && block <= task_last_block as u64;
			}).collect();
			let task = query_range_tasks.get_mut(their_node_id).unwrap();
			task.short_channel_ids.append(&mut filtered_short_channel_ids);
		}

		// The final message is indicated by a last_blocknum that is equal to
		// or greater than the query's last_blocknum.
		if msg_last_block >= task_last_block {
			log_debug!(self.logger, "Completed query_channel_range: peer={}, first_blocknum={}, number_of_blocks={}", log_pubkey!(their_node_id), task_first_blocknum, task_number_of_blocks);

			// We can now fire off a query to obtain routing messages for the
			// accumulated short_channel_ids.
			{
				let task = query_range_tasks.get_mut(their_node_id).unwrap();
				let mut short_channel_ids = Vec::new();
				std::mem::swap(&mut short_channel_ids, &mut task.short_channel_ids);
				self.query_short_channel_ids(their_node_id, task.chain_hash, short_channel_ids)?;
			}

			// We can remove the query range task now that the query is complete.
			query_range_tasks.remove(their_node_id);
		}
		Ok(())
	}

	/// When a query is initiated the remote peer will begin streaming
	/// gossip messages. In the event of a failure, we may have received
	/// some channel information. Before trying with another peer, the
	/// caller should update its set of SCIDs that need to be queried.
	fn handle_reply_short_channel_ids_end(&self, their_node_id: &PublicKey, msg: &ReplyShortChannelIdsEnd) -> Result<(), LightningError> {
		log_debug!(self.logger, "Handling reply_short_channel_ids_end peer={}, full_information={}", log_pubkey!(their_node_id), msg.full_information);

		// First we obtain a lock on the task hashmap. In order to avoid borrowing issues
		// we will access the task as needed.
		let mut query_short_channel_ids_tasks = self.scid_query_tasks.lock().unwrap();

		// If there is no existing task then we have received an unknown
		// message and should return an error.
		if query_short_channel_ids_tasks.get(their_node_id).is_none() {
			return Err(LightningError {
				err: String::from("Unknown reply_short_channel_ids_end message"),
				action: ErrorAction::IgnoreError,
			});
		}

		// If the reply's chain_hash does not match the task's chain_hash then
		// the reply is malformed and we should return an error.
		if msg.chain_hash != query_short_channel_ids_tasks.get(their_node_id).unwrap().chain_hash {
			query_short_channel_ids_tasks.remove(their_node_id);
			return Err(LightningError {
				err: String::from("Received reply_short_channel_ids_end with incorrect chain_hash"),
				action: ErrorAction::IgnoreError
			});
		}

		// If the remote node does not have up-to-date information for the
		// chain_hash they will set full_information=false. We can fail
		// the result and try again with a different peer.
		if !msg.full_information {
			query_short_channel_ids_tasks.remove(their_node_id);
			return Err(LightningError {
				err: String::from("Received reply_short_channel_ids_end with no information"),
				action: ErrorAction::IgnoreError
			});
		}

		// If we have more scids to process we send the next batch in the task
		{
			let task = query_short_channel_ids_tasks.get_mut(their_node_id).unwrap();
			if task.short_channel_ids.len() > 0 {
				self.finalize_query_short_ids(task);
				return Ok(());
			}
		}

		// Otherwise the task is complete and we can remove it
		log_debug!(self.logger, "Completed query_short_channel_ids peer={}", log_pubkey!(their_node_id));
		query_short_channel_ids_tasks.remove(their_node_id);
		Ok(())
	}

	/// There are potential DoS vectors when handling inbound queries.
	/// Handling requests with first_blocknum very far away may trigger repeated
	/// disk I/O if the NetworkGraph is not fully in-memory.
	fn handle_query_channel_range(&self, _their_node_id: &PublicKey, _msg: &QueryChannelRange) -> Result<(), LightningError> {
		// TODO
		Err(LightningError {
			err: String::from("Not implemented"),
			action: ErrorAction::IgnoreError,
		})
	}

	/// There are potential DoS vectors when handling inbound queries.
	/// Handling requests with first_blocknum very far away may trigger repeated
	/// disk I/O if the NetworkGraph is not fully in-memory.
	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: &QueryShortChannelIds) -> Result<(), LightningError> {
		// TODO
		Err(LightningError {
			err: String::from("Not implemented"),
			action: ErrorAction::IgnoreError,
		})
	}
}

impl<C: Deref, L: Deref> events::MessageSendEventsProvider for NetGraphMsgHandler<C, L>
where
	C::Target: chain::Access,
	L::Target: Logger,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		std::mem::swap(&mut ret, &mut pending_events);
		ret
	}
}

/// Safely calculates the last_blocknum given a first_blocknum and
/// number_of_blocks by returning the u32::MAX-1 if there is an overflow
fn last_blocknum(first_blocknum: u32, number_of_blocks: u32) -> u32 {
	match first_blocknum.checked_add(number_of_blocks) {
		Some(val) => val - 1,
		None => 0xffff_ffff - 1,
	}
}

/// Maintains state for a channel range query that we initiated.
/// The query may result in one or more reply_channel_range messages
/// being received. This struct helps determine the status of the query
/// when there are multiple replies. It also collects results for initiating
/// SCID queries.
///
/// The task is complete and can be cleaned up when a reply meets or
/// exceeds the last block in the query. The collected SCIDs in the task
/// can be used to generate an ScidQueryTask.
///
/// A query may fail if the recipient does not maintain up-to-date
/// information for the chain or if the recipient fails to reply within
/// a reasonable amount of time. In either event, the query can be
/// re-initiated with a different peer.
pub struct ChanRangeQueryTask {
	/// The public key of the node we will be sending queries to
	pub node_id: PublicKey,
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The height of the first block for the channel UTXOs being queried
	pub first_blocknum: u32,
	/// The number of blocks to include in the query results
	pub number_of_blocks: u32,
	/// Tracks the number of reply messages we have received
	pub number_of_replies: usize,
	/// The height of the first block received in a reply. This value
	/// should be less than or equal to the first_blocknum requested in
	/// the query_channel_range. This allows the range of the replies to
	/// contain, but not necessarily strictly, the queried range.
	pub received_first_block: Option<u32>,
	/// The height of the last block received in a reply. This value
	/// will get incrementally closer to the target of
	/// first_blocknum plus number_of_blocks from the query_channel_range.
	pub received_last_block: Option<u32>,
	/// Contains short_channel_ids received in one or more reply messages.
	/// These will be sent in one ore more query_short_channel_ids messages
	/// when the task is complete.
	pub short_channel_ids: Vec<u64>,
}

impl ChanRangeQueryTask {
	/// Constructs a new GossipQueryRangeTask
	pub fn new(their_node_id: &PublicKey, chain_hash: BlockHash, first_blocknum: u32, number_of_blocks: u32) -> Self {
		ChanRangeQueryTask {
			node_id: their_node_id.clone(),
			chain_hash,
			first_blocknum,
			number_of_blocks,
			number_of_replies: 0,
			received_first_block: None,
			received_last_block: None,
			short_channel_ids: vec![],
		}
	}
}

/// Maintains state when sending one or more short_channel_ids messages
/// to a peer. Only a single SCID query can be in-flight with a peer. The
/// number of SCIDs per query is limited by the size of a Lightning message
/// payload. When querying a large number of SCIDs (results of a large
/// channel range query for instance), multiple query_short_channel_ids
/// messages need to be sent. This task maintains the list of awaiting
/// SCIDs to be queried.
///
/// When a successful reply_short_channel_ids_end message is received, the
/// next batch of SCIDs can be sent. When no remaining SCIDs exist in the
/// task, the task is complete and can be cleaned up.
///
/// The recipient may reply indicating that up-to-date information for the
/// chain is not maintained. A query may also fail to complete within a
/// reasonable amount of time. In either event, the short_channel_ids
/// can be queried from a different peer after validating the set of
/// SCIDs that still need to be queried.
pub struct ScidQueryTask {
	/// The public key of the node we will be sending queries to
	pub node_id: PublicKey,
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// A vector of short_channel_ids that we would like routing gossip
	/// information for. This list will be chunked and sent to the peer
	/// in one or more query_short_channel_ids messages.
	pub short_channel_ids: Vec<u64>,
}

impl ScidQueryTask {
	/// Constructs a new GossipQueryShortChannelIdsTask
	pub fn new(their_node_id: &PublicKey, chain_hash: BlockHash, short_channel_ids: Vec<u64>) -> Self {
		ScidQueryTask {
			node_id: their_node_id.clone(),
			chain_hash,
			short_channel_ids,
		}
	}

	/// Adds short_channel_ids to the pending list of short_channel_ids
	/// to be sent in the next request. You can add additional values
	/// while a query is in-flight. These new values will be sent once
	/// the active query has completed.
	pub fn add(&mut self, mut short_channel_ids: Vec<u64>) {
		self.short_channel_ids.append(&mut short_channel_ids);
	}
}

#[derive(PartialEq, Debug)]
/// Details about one direction of a channel. Received
/// within a channel update.
pub struct DirectionalChannelInfo {
	/// When the last update to the channel direction was issued.
	/// Value is opaque, as set in the announcement.
	pub last_update: u32,
	/// Whether the channel can be currently used for payments (in this one direction).
	pub enabled: bool,
	/// The difference in CLTV values that you must have when routing through this channel.
	pub cltv_expiry_delta: u16,
	/// The minimum value, which must be relayed to the next hop via the channel
	pub htlc_minimum_msat: u64,
	/// The maximum value which may be relayed to the next hop via the channel.
	pub htlc_maximum_msat: Option<u64>,
	/// Fees charged when the channel is used for routing
	pub fees: RoutingFees,
	/// Most recent update for the channel received from the network
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub last_update_message: Option<ChannelUpdate>,
}

impl fmt::Display for DirectionalChannelInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "last_update {}, enabled {}, cltv_expiry_delta {}, htlc_minimum_msat {}, fees {:?}", self.last_update, self.enabled, self.cltv_expiry_delta, self.htlc_minimum_msat, self.fees)?;
		Ok(())
	}
}

impl_writeable!(DirectionalChannelInfo, 0, {
	last_update,
	enabled,
	cltv_expiry_delta,
	htlc_minimum_msat,
	htlc_maximum_msat,
	fees,
	last_update_message
});

#[derive(PartialEq)]
/// Details about a channel (both directions).
/// Received within a channel announcement.
pub struct ChannelInfo {
	/// Protocol features of a channel communicated during its announcement
	pub features: ChannelFeatures,
	/// Source node of the first direction of a channel
	pub node_one: PublicKey,
	/// Details about the first direction of a channel
	pub one_to_two: Option<DirectionalChannelInfo>,
	/// Source node of the second direction of a channel
	pub node_two: PublicKey,
	/// Details about the second direction of a channel
	pub two_to_one: Option<DirectionalChannelInfo>,
	/// The channel capacity as seen on-chain, if chain lookup is available.
	pub capacity_sats: Option<u64>,
	/// An initial announcement of the channel
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub announcement_message: Option<ChannelAnnouncement>,
}

impl fmt::Display for ChannelInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "features: {}, node_one: {}, one_to_two: {:?}, node_two: {}, two_to_one: {:?}",
		   log_bytes!(self.features.encode()), log_pubkey!(self.node_one), self.one_to_two, log_pubkey!(self.node_two), self.two_to_one)?;
		Ok(())
	}
}

impl_writeable!(ChannelInfo, 0, {
	features,
	node_one,
	one_to_two,
	node_two,
	two_to_one,
	capacity_sats,
	announcement_message
});


/// Fees for routing via a given channel or a node
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct RoutingFees {
	/// Flat routing fee in satoshis
	pub base_msat: u32,
	/// Liquidity-based routing fee in millionths of a routed amount.
	/// In other words, 10000 is 1%.
	pub proportional_millionths: u32,
}

impl Readable for RoutingFees{
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<RoutingFees, DecodeError> {
		let base_msat: u32 = Readable::read(reader)?;
		let proportional_millionths: u32 = Readable::read(reader)?;
		Ok(RoutingFees {
			base_msat,
			proportional_millionths,
		})
	}
}

impl Writeable for RoutingFees {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.base_msat.write(writer)?;
		self.proportional_millionths.write(writer)?;
		Ok(())
	}
}

#[derive(PartialEq, Debug)]
/// Information received in the latest node_announcement from this node.
pub struct NodeAnnouncementInfo {
	/// Protocol features the node announced support for
	pub features: NodeFeatures,
	/// When the last known update to the node state was issued.
	/// Value is opaque, as set in the announcement.
	pub last_update: u32,
	/// Color assigned to the node
	pub rgb: [u8; 3],
	/// Moniker assigned to the node.
	/// May be invalid or malicious (eg control chars),
	/// should not be exposed to the user.
	pub alias: [u8; 32],
	/// Internet-level addresses via which one can connect to the node
	pub addresses: Vec<NetAddress>,
	/// An initial announcement of the node
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub announcement_message: Option<NodeAnnouncement>
}

impl Writeable for NodeAnnouncementInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.features.write(writer)?;
		self.last_update.write(writer)?;
		self.rgb.write(writer)?;
		self.alias.write(writer)?;
		(self.addresses.len() as u64).write(writer)?;
		for ref addr in &self.addresses {
			addr.write(writer)?;
		}
		self.announcement_message.write(writer)?;
		Ok(())
	}
}

impl Readable for NodeAnnouncementInfo {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<NodeAnnouncementInfo, DecodeError> {
		let features = Readable::read(reader)?;
		let last_update = Readable::read(reader)?;
		let rgb = Readable::read(reader)?;
		let alias = Readable::read(reader)?;
		let addresses_count: u64 = Readable::read(reader)?;
		let mut addresses = Vec::with_capacity(cmp::min(addresses_count, MAX_ALLOC_SIZE / 40) as usize);
		for _ in 0..addresses_count {
			match Readable::read(reader) {
				Ok(Ok(addr)) => { addresses.push(addr); },
				Ok(Err(_)) => return Err(DecodeError::InvalidValue),
				Err(DecodeError::ShortRead) => return Err(DecodeError::BadLengthDescriptor),
				_ => unreachable!(),
			}
		}
		let announcement_message = Readable::read(reader)?;
		Ok(NodeAnnouncementInfo {
			features,
			last_update,
			rgb,
			alias,
			addresses,
			announcement_message
		})
	}
}

#[derive(PartialEq)]
/// Details about a node in the network, known from the network announcement.
pub struct NodeInfo {
	/// All valid channels a node has announced
	pub channels: Vec<u64>,
	/// Lowest fees enabling routing via any of the enabled, known channels to a node.
	/// The two fields (flat and proportional fee) are independent,
	/// meaning they don't have to refer to the same channel.
	pub lowest_inbound_channel_fees: Option<RoutingFees>,
	/// More information about a node from node_announcement.
	/// Optional because we store a Node entry after learning about it from
	/// a channel announcement, but before receiving a node announcement.
	pub announcement_info: Option<NodeAnnouncementInfo>
}

impl fmt::Display for NodeInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "lowest_inbound_channel_fees: {:?}, channels: {:?}, announcement_info: {:?}",
		   self.lowest_inbound_channel_fees, &self.channels[..], self.announcement_info)?;
		Ok(())
	}
}

impl Writeable for NodeInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.channels.len() as u64).write(writer)?;
		for ref chan in self.channels.iter() {
			chan.write(writer)?;
		}
		self.lowest_inbound_channel_fees.write(writer)?;
		self.announcement_info.write(writer)?;
		Ok(())
	}
}

const MAX_ALLOC_SIZE: u64 = 64*1024;

impl Readable for NodeInfo {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<NodeInfo, DecodeError> {
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = Vec::with_capacity(cmp::min(channels_count, MAX_ALLOC_SIZE / 8) as usize);
		for _ in 0..channels_count {
			channels.push(Readable::read(reader)?);
		}
		let lowest_inbound_channel_fees = Readable::read(reader)?;
		let announcement_info = Readable::read(reader)?;
		Ok(NodeInfo {
			channels,
			lowest_inbound_channel_fees,
			announcement_info,
		})
	}
}

impl Writeable for NetworkGraph {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.genesis_hash.write(writer)?;
		(self.channels.len() as u64).write(writer)?;
		for (ref chan_id, ref chan_info) in self.channels.iter() {
			(*chan_id).write(writer)?;
			chan_info.write(writer)?;
		}
		(self.nodes.len() as u64).write(writer)?;
		for (ref node_id, ref node_info) in self.nodes.iter() {
			node_id.write(writer)?;
			node_info.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for NetworkGraph {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<NetworkGraph, DecodeError> {
		let genesis_hash: BlockHash = Readable::read(reader)?;
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = BTreeMap::new();
		for _ in 0..channels_count {
			let chan_id: u64 = Readable::read(reader)?;
			let chan_info = Readable::read(reader)?;
			channels.insert(chan_id, chan_info);
		}
		let nodes_count: u64 = Readable::read(reader)?;
		let mut nodes = BTreeMap::new();
		for _ in 0..nodes_count {
			let node_id = Readable::read(reader)?;
			let node_info = Readable::read(reader)?;
			nodes.insert(node_id, node_info);
		}
		Ok(NetworkGraph {
			genesis_hash,
			channels,
			nodes,
		})
	}
}

impl fmt::Display for NetworkGraph {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "Network map\n[Channels]")?;
		for (key, val) in self.channels.iter() {
			writeln!(f, " {}: {}", key, val)?;
		}
		writeln!(f, "[Nodes]")?;
		for (key, val) in self.nodes.iter() {
			writeln!(f, " {}: {}", log_pubkey!(key), val)?;
		}
		Ok(())
	}
}

impl NetworkGraph {
	/// Returns all known valid channels' short ids along with announced channel info.
	///
	/// (C-not exported) because we have no mapping for `BTreeMap`s
	pub fn get_channels<'a>(&'a self) -> &'a BTreeMap<u64, ChannelInfo> { &self.channels }
	/// Returns all known nodes' public keys along with announced node info.
	///
	/// (C-not exported) because we have no mapping for `BTreeMap`s
	pub fn get_nodes<'a>(&'a self) -> &'a BTreeMap<PublicKey, NodeInfo> { &self.nodes }

	/// Get network addresses by node id.
	/// Returns None if the requested node is completely unknown,
	/// or if node announcement for the node was never received.
	///
	/// (C-not exported) as there is no practical way to track lifetimes of returned values.
	pub fn get_addresses<'a>(&'a self, pubkey: &PublicKey) -> Option<&'a Vec<NetAddress>> {
		if let Some(node) = self.nodes.get(pubkey) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				return Some(&node_info.addresses)
			}
		}
		None
	}

	/// Creates a new, empty, network graph.
	pub fn new(genesis_hash: BlockHash) -> NetworkGraph {
		Self {
			genesis_hash,
			channels: BTreeMap::new(),
			nodes: BTreeMap::new(),
		}
	}

	/// For an already known node (from channel announcements), update its stored properties from a
	/// given node announcement.
	///
	/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	pub fn update_node_from_announcement<T: secp256k1::Verification>(&mut self, msg: &msgs::NodeAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<(), LightningError> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.signature, &msg.contents.node_id);
		self.update_node_from_announcement_intern(&msg.contents, Some(&msg))
	}

	/// For an already known node (from channel announcements), update its stored properties from a
	/// given node announcement without verifying the associated signatures. Because we aren't
	/// given the associated signatures here we cannot relay the node announcement to any of our
	/// peers.
	pub fn update_node_from_unsigned_announcement(&mut self, msg: &msgs::UnsignedNodeAnnouncement) -> Result<(), LightningError> {
		self.update_node_from_announcement_intern(msg, None)
	}

	fn update_node_from_announcement_intern(&mut self, msg: &msgs::UnsignedNodeAnnouncement, full_msg: Option<&msgs::NodeAnnouncement>) -> Result<(), LightningError> {
		match self.nodes.get_mut(&msg.node_id) {
			None => Err(LightningError{err: "No existing channels for node_announcement".to_owned(), action: ErrorAction::IgnoreError}),
			Some(node) => {
				if let Some(node_info) = node.announcement_info.as_ref() {
					if node_info.last_update  >= msg.timestamp {
						return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreError});
					}
				}

				let should_relay = msg.excess_data.is_empty() && msg.excess_address_data.is_empty();
				node.announcement_info = Some(NodeAnnouncementInfo {
					features: msg.features.clone(),
					last_update: msg.timestamp,
					rgb: msg.rgb,
					alias: msg.alias,
					addresses: msg.addresses.clone(),
					announcement_message: if should_relay { full_msg.cloned() } else { None },
				});

				Ok(())
			}
		}
	}

	/// Store or update channel info from a channel announcement.
	///
	/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	///
	/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
	/// the corresponding UTXO exists on chain and is correctly-formatted.
	pub fn update_channel_from_announcement<T: secp256k1::Verification, C: Deref>
			(&mut self, msg: &msgs::ChannelAnnouncement, chain_access: &Option<C>, secp_ctx: &Secp256k1<T>)
			-> Result<(), LightningError>
			where C::Target: chain::Access {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.node_signature_1, &msg.contents.node_id_1);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.node_signature_2, &msg.contents.node_id_2);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.bitcoin_signature_1, &msg.contents.bitcoin_key_1);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.bitcoin_signature_2, &msg.contents.bitcoin_key_2);
		self.update_channel_from_unsigned_announcement_intern(&msg.contents, Some(msg), chain_access)
	}

	/// Store or update channel info from a channel announcement without verifying the associated
	/// signatures. Because we aren't given the associated signatures here we cannot relay the
	/// channel announcement to any of our peers.
	///
	/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
	/// the corresponding UTXO exists on chain and is correctly-formatted.
	pub fn update_channel_from_unsigned_announcement<C: Deref>
			(&mut self, msg: &msgs::UnsignedChannelAnnouncement, chain_access: &Option<C>)
			-> Result<(), LightningError>
			where C::Target: chain::Access {
		self.update_channel_from_unsigned_announcement_intern(msg, None, chain_access)
	}

	fn update_channel_from_unsigned_announcement_intern<C: Deref>
			(&mut self, msg: &msgs::UnsignedChannelAnnouncement, full_msg: Option<&msgs::ChannelAnnouncement>, chain_access: &Option<C>)
			-> Result<(), LightningError>
			where C::Target: chain::Access {
		if msg.node_id_1 == msg.node_id_2 || msg.bitcoin_key_1 == msg.bitcoin_key_2 {
			return Err(LightningError{err: "Channel announcement node had a channel with itself".to_owned(), action: ErrorAction::IgnoreError});
		}

		let utxo_value = match &chain_access {
			&None => {
				// Tentatively accept, potentially exposing us to DoS attacks
				None
			},
			&Some(ref chain_access) => {
				match chain_access.get_utxo(&msg.chain_hash, msg.short_channel_id) {
					Ok(TxOut { value, script_pubkey }) => {
						let expected_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
						                                    .push_slice(&msg.bitcoin_key_1.serialize())
						                                    .push_slice(&msg.bitcoin_key_2.serialize())
						                                    .push_opcode(opcodes::all::OP_PUSHNUM_2)
						                                    .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();
						if script_pubkey != expected_script {
							return Err(LightningError{err: format!("Channel announcement key ({}) didn't match on-chain script ({})", script_pubkey.to_hex(), expected_script.to_hex()), action: ErrorAction::IgnoreError});
						}
						//TODO: Check if value is worth storing, use it to inform routing, and compare it
						//to the new HTLC max field in channel_update
						Some(value)
					},
					Err(chain::AccessError::UnknownChain) => {
						return Err(LightningError{err: format!("Channel announced on an unknown chain ({})", msg.chain_hash.encode().to_hex()), action: ErrorAction::IgnoreError});
					},
					Err(chain::AccessError::UnknownTx) => {
						return Err(LightningError{err: "Channel announced without corresponding UTXO entry".to_owned(), action: ErrorAction::IgnoreError});
					},
				}
			},
		};

		let chan_info = ChannelInfo {
				features: msg.features.clone(),
				node_one: msg.node_id_1.clone(),
				one_to_two: None,
				node_two: msg.node_id_2.clone(),
				two_to_one: None,
				capacity_sats: utxo_value,
				announcement_message: if msg.excess_data.is_empty() { full_msg.cloned() } else { None },
			};

		match self.channels.entry(msg.short_channel_id) {
			BtreeEntry::Occupied(mut entry) => {
				//TODO: because asking the blockchain if short_channel_id is valid is only optional
				//in the blockchain API, we need to handle it smartly here, though it's unclear
				//exactly how...
				if utxo_value.is_some() {
					// Either our UTXO provider is busted, there was a reorg, or the UTXO provider
					// only sometimes returns results. In any case remove the previous entry. Note
					// that the spec expects us to "blacklist" the node_ids involved, but we can't
					// do that because
					// a) we don't *require* a UTXO provider that always returns results.
					// b) we don't track UTXOs of channels we know about and remove them if they
					//    get reorg'd out.
					// c) it's unclear how to do so without exposing ourselves to massive DoS risk.
					Self::remove_channel_in_nodes(&mut self.nodes, &entry.get(), msg.short_channel_id);
					*entry.get_mut() = chan_info;
				} else {
					return Err(LightningError{err: "Already have knowledge of channel".to_owned(), action: ErrorAction::IgnoreError})
				}
			},
			BtreeEntry::Vacant(entry) => {
				entry.insert(chan_info);
			}
		};

		macro_rules! add_channel_to_node {
			( $node_id: expr ) => {
				match self.nodes.entry($node_id) {
					BtreeEntry::Occupied(node_entry) => {
						node_entry.into_mut().channels.push(msg.short_channel_id);
					},
					BtreeEntry::Vacant(node_entry) => {
						node_entry.insert(NodeInfo {
							channels: vec!(msg.short_channel_id),
							lowest_inbound_channel_fees: None,
							announcement_info: None,
						});
					}
				}
			};
		}

		add_channel_to_node!(msg.node_id_1);
		add_channel_to_node!(msg.node_id_2);

		Ok(())
	}

	/// Close a channel if a corresponding HTLC fail was sent.
	/// If permanent, removes a channel from the local storage.
	/// May cause the removal of nodes too, if this was their last channel.
	/// If not permanent, makes channels unavailable for routing.
	pub fn close_channel_from_update(&mut self, short_channel_id: u64, is_permanent: bool) {
		if is_permanent {
			if let Some(chan) = self.channels.remove(&short_channel_id) {
				Self::remove_channel_in_nodes(&mut self.nodes, &chan, short_channel_id);
			}
		} else {
			if let Some(chan) = self.channels.get_mut(&short_channel_id) {
				if let Some(one_to_two) = chan.one_to_two.as_mut() {
					one_to_two.enabled = false;
				}
				if let Some(two_to_one) = chan.two_to_one.as_mut() {
					two_to_one.enabled = false;
				}
			}
		}
	}

	fn fail_node(&mut self, _node_id: &PublicKey, is_permanent: bool) {
		if is_permanent {
			// TODO: Wholly remove the node
		} else {
			// TODO: downgrade the node
		}
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel.
	///
	/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	pub fn update_channel<T: secp256k1::Verification>(&mut self, msg: &msgs::ChannelUpdate, secp_ctx: &Secp256k1<T>) -> Result<(), LightningError> {
		self.update_channel_intern(&msg.contents, Some(&msg), Some((&msg.signature, secp_ctx)))
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel without verifying the associated signatures. Because we aren't given the
	/// associated signatures here we cannot relay the channel update to any of our peers.
	pub fn update_channel_unsigned(&mut self, msg: &msgs::UnsignedChannelUpdate) -> Result<(), LightningError> {
		self.update_channel_intern(msg, None, None::<(&secp256k1::Signature, &Secp256k1<secp256k1::VerifyOnly>)>)
	}

	fn update_channel_intern<T: secp256k1::Verification>(&mut self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>, sig_info: Option<(&secp256k1::Signature, &Secp256k1<T>)>) -> Result<(), LightningError> {
		let dest_node_id;
		let chan_enabled = msg.flags & (1 << 1) != (1 << 1);
		let chan_was_enabled;

		match self.channels.get_mut(&msg.short_channel_id) {
			None => return Err(LightningError{err: "Couldn't find channel for update".to_owned(), action: ErrorAction::IgnoreError}),
			Some(channel) => {
				if let OptionalField::Present(htlc_maximum_msat) = msg.htlc_maximum_msat {
					if htlc_maximum_msat > MAX_VALUE_MSAT {
						return Err(LightningError{err: "htlc_maximum_msat is larger than maximum possible msats".to_owned(), action: ErrorAction::IgnoreError});
					}

					if let Some(capacity_sats) = channel.capacity_sats {
						// It's possible channel capacity is available now, although it wasn't available at announcement (so the field is None).
						// Don't query UTXO set here to reduce DoS risks.
						if capacity_sats > MAX_VALUE_MSAT / 1000 || htlc_maximum_msat > capacity_sats * 1000 {
							return Err(LightningError{err: "htlc_maximum_msat is larger than channel capacity or capacity is bogus".to_owned(), action: ErrorAction::IgnoreError});
						}
					}
				}
				macro_rules! maybe_update_channel_info {
					( $target: expr, $src_node: expr) => {
						if let Some(existing_chan_info) = $target.as_ref() {
							if existing_chan_info.last_update >= msg.timestamp {
								return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreError});
							}
							chan_was_enabled = existing_chan_info.enabled;
						} else {
							chan_was_enabled = false;
						}

						let last_update_message = if msg.excess_data.is_empty() { full_msg.cloned() } else { None };

						let updated_channel_dir_info = DirectionalChannelInfo {
							enabled: chan_enabled,
							last_update: msg.timestamp,
							cltv_expiry_delta: msg.cltv_expiry_delta,
							htlc_minimum_msat: msg.htlc_minimum_msat,
							htlc_maximum_msat: if let OptionalField::Present(max_value) = msg.htlc_maximum_msat { Some(max_value) } else { None },
							fees: RoutingFees {
								base_msat: msg.fee_base_msat,
								proportional_millionths: msg.fee_proportional_millionths,
							},
							last_update_message
						};
						$target = Some(updated_channel_dir_info);
					}
				}

				let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
				if msg.flags & 1 == 1 {
					dest_node_id = channel.node_one.clone();
					if let Some((sig, ctx)) = sig_info {
						secp_verify_sig!(ctx, &msg_hash, &sig, &channel.node_two);
					}
					maybe_update_channel_info!(channel.two_to_one, channel.node_two);
				} else {
					dest_node_id = channel.node_two.clone();
					if let Some((sig, ctx)) = sig_info {
						secp_verify_sig!(ctx, &msg_hash, &sig, &channel.node_one);
					}
					maybe_update_channel_info!(channel.one_to_two, channel.node_one);
				}
			}
		}

		if chan_enabled {
			let node = self.nodes.get_mut(&dest_node_id).unwrap();
			let mut base_msat = msg.fee_base_msat;
			let mut proportional_millionths = msg.fee_proportional_millionths;
			if let Some(fees) = node.lowest_inbound_channel_fees {
				base_msat = cmp::min(base_msat, fees.base_msat);
				proportional_millionths = cmp::min(proportional_millionths, fees.proportional_millionths);
			}
			node.lowest_inbound_channel_fees = Some(RoutingFees {
				base_msat,
				proportional_millionths
			});
		} else if chan_was_enabled {
			let node = self.nodes.get_mut(&dest_node_id).unwrap();
			let mut lowest_inbound_channel_fees = None;

			for chan_id in node.channels.iter() {
				let chan = self.channels.get(chan_id).unwrap();
				let chan_info_opt;
				if chan.node_one == dest_node_id {
					chan_info_opt = chan.two_to_one.as_ref();
				} else {
					chan_info_opt = chan.one_to_two.as_ref();
				}
				if let Some(chan_info) = chan_info_opt {
					if chan_info.enabled {
						let fees = lowest_inbound_channel_fees.get_or_insert(RoutingFees {
							base_msat: u32::max_value(), proportional_millionths: u32::max_value() });
						fees.base_msat = cmp::min(fees.base_msat, chan_info.fees.base_msat);
						fees.proportional_millionths = cmp::min(fees.proportional_millionths, chan_info.fees.proportional_millionths);
					}
				}
			}

			node.lowest_inbound_channel_fees = lowest_inbound_channel_fees;
		}

		Ok(())
	}

	fn remove_channel_in_nodes(nodes: &mut BTreeMap<PublicKey, NodeInfo>, chan: &ChannelInfo, short_channel_id: u64) {
		macro_rules! remove_from_node {
			($node_id: expr) => {
				if let BtreeEntry::Occupied(mut entry) = nodes.entry($node_id) {
					entry.get_mut().channels.retain(|chan_id| {
						short_channel_id != *chan_id
					});
					if entry.get().channels.is_empty() {
						entry.remove_entry();
					}
				} else {
					panic!("Had channel that pointed to unknown node (ie inconsistent network map)!");
				}
			}
		}

		remove_from_node!(chan.node_one);
		remove_from_node!(chan.node_two);
	}
}

#[cfg(test)]
mod tests {
	use chain;
	use ln::features::{ChannelFeatures, NodeFeatures};
	use routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
	use ln::msgs::{OptionalField, RoutingMessageHandler, UnsignedNodeAnnouncement, NodeAnnouncement,
		UnsignedChannelAnnouncement, ChannelAnnouncement, UnsignedChannelUpdate, ChannelUpdate, HTLCFailChannelUpdate,
		ReplyChannelRange, ReplyShortChannelIdsEnd, QueryChannelRange, QueryShortChannelIds, MAX_VALUE_MSAT};
	use util::test_utils;
	use util::logger::Logger;
	use util::ser::{Readable, Writeable};
	use util::events::{MessageSendEvent, MessageSendEventsProvider};

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::transaction::TxOut;
	use bitcoin::blockdata::opcodes;

	use hex;

	use bitcoin::secp256k1::key::{PublicKey, SecretKey};
	use bitcoin::secp256k1::{All, Secp256k1};

	use std::sync::Arc;

	fn create_net_graph_msg_handler() -> (Secp256k1<All>, NetGraphMsgHandler<Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let net_graph_msg_handler = NetGraphMsgHandler::new(genesis_hash, None, Arc::clone(&logger));
		(secp_ctx, net_graph_msg_handler)
	}

	#[test]
	fn request_full_sync_finite_times() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()[..]).unwrap());

		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(!net_graph_msg_handler.should_request_full_sync(&node_id));
	}

	#[test]
	fn handling_node_announcements() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();
		let zero_hash = Sha256dHash::hash(&[0; 32]);
		let first_announcement_time = 500;

		let mut unsigned_announcement = UnsignedNodeAnnouncement {
			features: NodeFeatures::known(),
			timestamp: first_announcement_time,
			node_id: node_id_1,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let mut msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_announcement.clone()
		};

		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!("No existing channels for node_announcement", e.err)
		};

		{
			// Announce a channel to add a corresponding node.
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::known(),
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: 0,
				node_id_1,
				node_id_2,
				bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
				bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
				excess_data: Vec::new(),
			};

			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
				node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
				bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
				bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
				contents: unsigned_announcement.clone(),
			};
			match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
				Ok(res) => assert!(res),
				_ => panic!()
			};
		}

		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			Err(_) => panic!()
		};

		let fake_msghash = hash_to_message!(&zero_hash);
		match net_graph_msg_handler.handle_node_announcement(
			&NodeAnnouncement {
				signature: secp_ctx.sign(&fake_msghash, node_1_privkey),
				contents: unsigned_announcement.clone()
		}) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature from remote node")
		};

		unsigned_announcement.timestamp += 1000;
		unsigned_announcement.excess_data.push(1);
		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let announcement_with_data = NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_announcement.clone()
		};
		// Return false because contains excess data.
		match net_graph_msg_handler.handle_node_announcement(&announcement_with_data) {
			Ok(res) => assert!(!res),
			Err(_) => panic!()
		};
		unsigned_announcement.excess_data = Vec::new();

		// Even though previous announcement was not relayed further, we still accepted it,
		// so we now won't accept announcements before the previous one.
		unsigned_announcement.timestamp -= 10;
		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let outdated_announcement = NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_announcement.clone()
		};
		match net_graph_msg_handler.handle_node_announcement(&outdated_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Update older than last processed update")
		};
	}

	#[test]
	fn handling_channel_announcements() {
		let secp_ctx = Secp256k1::new();
		let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::new());

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let good_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
		   .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_1_btckey).serialize())
		   .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_2_btckey).serialize())
		   .push_opcode(opcodes::all::OP_PUSHNUM_2)
		   .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();


		let mut unsigned_announcement = UnsignedChannelAnnouncement {
			features: ChannelFeatures::known(),
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 0,
			node_id_1,
			node_id_2,
			bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
			bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
			excess_data: Vec::new(),
		};

		let mut msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};

		// Test if the UTXO lookups were not supported
		let mut net_graph_msg_handler = NetGraphMsgHandler::new(genesis_block(Network::Testnet).header.block_hash(), None, Arc::clone(&logger));
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&unsigned_announcement.short_channel_id) {
				None => panic!(),
				Some(_) => ()
			}
		}

		// If we receive announcement for the same channel (with UTXO lookups disabled),
		// drop new one on the floor, since we can't see any changes.
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Already have knowledge of channel")
		};

		// Test if an associated transaction were not on-chain (or not confirmed).
		let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		*chain_source.utxo_ret.lock().unwrap() = Err(chain::AccessError::UnknownTx);
		net_graph_msg_handler = NetGraphMsgHandler::new(chain_source.clone().genesis_hash, Some(chain_source.clone()), Arc::clone(&logger));
		unsigned_announcement.short_channel_id += 1;

		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};

		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announced without corresponding UTXO entry")
		};

		// Now test if the transaction is found in the UTXO set and the script is correct.
		unsigned_announcement.short_channel_id += 1;
		*chain_source.utxo_ret.lock().unwrap() = Ok(TxOut { value: 0, script_pubkey: good_script.clone() });

		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&unsigned_announcement.short_channel_id) {
				None => panic!(),
				Some(_) => ()
			}
		}

		// If we receive announcement for the same channel (but TX is not confirmed),
		// drop new one on the floor, since we can't see any changes.
		*chain_source.utxo_ret.lock().unwrap() = Err(chain::AccessError::UnknownTx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announced without corresponding UTXO entry")
		};

		// But if it is confirmed, replace the channel
		*chain_source.utxo_ret.lock().unwrap() = Ok(TxOut { value: 0, script_pubkey: good_script });
		unsigned_announcement.features = ChannelFeatures::empty();
		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};
		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&unsigned_announcement.short_channel_id) {
				Some(channel_entry) => {
					assert_eq!(channel_entry.features, ChannelFeatures::empty());
				},
				_ => panic!()
			}
		}

		// Don't relay valid channels with excess data
		unsigned_announcement.short_channel_id += 1;
		unsigned_announcement.excess_data.push(1);
		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};

		unsigned_announcement.excess_data = Vec::new();
		let invalid_sig_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_1_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&invalid_sig_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature from remote node")
		};

		unsigned_announcement.node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let channel_to_itself_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_2_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&channel_to_itself_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announcement node had a channel with itself")
		};
	}

	#[test]
	fn handling_channel_update() {
		let secp_ctx = Secp256k1::new();
		let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let net_graph_msg_handler = NetGraphMsgHandler::new(genesis_block(Network::Testnet).header.block_hash(), Some(chain_source.clone()), Arc::clone(&logger));

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let zero_hash = Sha256dHash::hash(&[0; 32]);
		let short_channel_id = 0;
		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let amount_sats = 1000_000;

		{
			// Announce a channel we will update
			let good_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
			   .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_1_btckey).serialize())
			   .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_2_btckey).serialize())
			   .push_opcode(opcodes::all::OP_PUSHNUM_2)
			   .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();
			*chain_source.utxo_ret.lock().unwrap() = Ok(TxOut { value: amount_sats, script_pubkey: good_script.clone() });
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash,
				short_channel_id,
				node_id_1,
				node_id_2,
				bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
				bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
				excess_data: Vec::new(),
			};

			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_channel_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
				node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
				bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
				bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
				contents: unsigned_announcement.clone(),
			};
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

		}

		let mut unsigned_channel_update = UnsignedChannelUpdate {
			chain_hash,
			short_channel_id,
			timestamp: 100,
			flags: 0,
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1000000,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 10000,
			fee_proportional_millionths: 20,
			excess_data: Vec::new()
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert_eq!(channel_info.one_to_two.as_ref().unwrap().cltv_expiry_delta, 144);
					assert!(channel_info.two_to_one.is_none());
				}
			}
		}

		unsigned_channel_update.timestamp += 100;
		unsigned_channel_update.excess_data.push(1);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};
		// Return false because contains excess data
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};
		unsigned_channel_update.timestamp += 10;

		unsigned_channel_update.short_channel_id += 1;
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Couldn't find channel for update")
		};
		unsigned_channel_update.short_channel_id = short_channel_id;

		unsigned_channel_update.htlc_maximum_msat = OptionalField::Present(MAX_VALUE_MSAT + 1);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than maximum possible msats")
		};
		unsigned_channel_update.htlc_maximum_msat = OptionalField::Absent;

		unsigned_channel_update.htlc_maximum_msat = OptionalField::Present(amount_sats * 1000 + 1);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than channel capacity or capacity is bogus")
		};
		unsigned_channel_update.htlc_maximum_msat = OptionalField::Absent;

		// Even though previous update was not relayed further, we still accepted it,
		// so we now won't accept update before the previous one.
		unsigned_channel_update.timestamp -= 10;
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Update older than last processed update")
		};
		unsigned_channel_update.timestamp += 500;

		let fake_msghash = hash_to_message!(&zero_hash);
		let invalid_sig_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&fake_msghash, node_1_privkey),
			contents: unsigned_channel_update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&invalid_sig_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature from remote node")
		};

	}

	#[test]
	fn handling_htlc_fail_channel_update() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let short_channel_id = 0;
		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		{
			// There is no nodes in the table at the beginning.
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			assert_eq!(network.get_nodes().len(), 0);
		}

		{
			// Announce a channel we will update
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash,
				short_channel_id,
				node_id_1,
				node_id_2,
				bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
				bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
				excess_data: Vec::new(),
			};

			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_channel_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
				node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
				bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
				bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
				contents: unsigned_announcement.clone(),
			};
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

			let unsigned_channel_update = UnsignedChannelUpdate {
				chain_hash,
				short_channel_id,
				timestamp: 100,
				flags: 0,
				cltv_expiry_delta: 144,
				htlc_minimum_msat: 1000000,
				htlc_maximum_msat: OptionalField::Absent,
				fee_base_msat: 10000,
				fee_proportional_millionths: 20,
				excess_data: Vec::new()
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
			let valid_channel_update = ChannelUpdate {
				signature: secp_ctx.sign(&msghash, node_1_privkey),
				contents: unsigned_channel_update.clone()
			};

			match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
				Ok(res) => assert!(res),
				_ => panic!()
			};
		}

		// Non-permanent closing just disables a channel
		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(channel_info.one_to_two.is_some());
				}
			}
		}

		let channel_close_msg = HTLCFailChannelUpdate::ChannelClosed {
			short_channel_id,
			is_permanent: false
		};

		net_graph_msg_handler.handle_htlc_fail_channel_update(&channel_close_msg);

		// Non-permanent closing just disables a channel
		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			match network.get_channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(!channel_info.one_to_two.as_ref().unwrap().enabled);
				}
			}
		}

		let channel_close_msg = HTLCFailChannelUpdate::ChannelClosed {
			short_channel_id,
			is_permanent: true
		};

		net_graph_msg_handler.handle_htlc_fail_channel_update(&channel_close_msg);

		// Permanent closing deletes a channel
		{
			let network = net_graph_msg_handler.network_graph.read().unwrap();
			assert_eq!(network.get_channels().len(), 0);
			// Nodes are also deleted because there are no associated channels anymore
			assert_eq!(network.get_nodes().len(), 0);
		}
		// TODO: Test HTLCFailChannelUpdate::NodeFailure, which is not implemented yet.
	}

	#[test]
	fn getting_next_channel_announcements() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let short_channel_id = 1;
		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// Channels were not announced yet.
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(0, 1);
		assert_eq!(channels_with_announcements.len(), 0);

		{
			// Announce a channel we will update
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash,
				short_channel_id,
				node_id_1,
				node_id_2,
				bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
				bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
				excess_data: Vec::new(),
			};

			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_channel_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
				node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
				bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
				bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
				contents: unsigned_announcement.clone(),
			};
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Contains initial channel announcement now.
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(short_channel_id, 1);
		assert_eq!(channels_with_announcements.len(), 1);
		if let Some(channel_announcements) = channels_with_announcements.first() {
			let &(_, ref update_1, ref update_2) = channel_announcements;
			assert_eq!(update_1, &None);
			assert_eq!(update_2, &None);
		} else {
			panic!();
		}


		{
			// Valid channel update
			let unsigned_channel_update = UnsignedChannelUpdate {
				chain_hash,
				short_channel_id,
				timestamp: 101,
				flags: 0,
				cltv_expiry_delta: 144,
				htlc_minimum_msat: 1000000,
				htlc_maximum_msat: OptionalField::Absent,
				fee_base_msat: 10000,
				fee_proportional_millionths: 20,
				excess_data: Vec::new()
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
			let valid_channel_update = ChannelUpdate {
				signature: secp_ctx.sign(&msghash, node_1_privkey),
				contents: unsigned_channel_update.clone()
			};
			match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Now contains an initial announcement and an update.
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(short_channel_id, 1);
		assert_eq!(channels_with_announcements.len(), 1);
		if let Some(channel_announcements) = channels_with_announcements.first() {
			let &(_, ref update_1, ref update_2) = channel_announcements;
			assert_ne!(update_1, &None);
			assert_eq!(update_2, &None);
		} else {
			panic!();
		}


		{
			// Channel update with excess data.
			let unsigned_channel_update = UnsignedChannelUpdate {
				chain_hash,
				short_channel_id,
				timestamp: 102,
				flags: 0,
				cltv_expiry_delta: 144,
				htlc_minimum_msat: 1000000,
				htlc_maximum_msat: OptionalField::Absent,
				fee_base_msat: 10000,
				fee_proportional_millionths: 20,
				excess_data: [1; 3].to_vec()
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
			let valid_channel_update = ChannelUpdate {
				signature: secp_ctx.sign(&msghash, node_1_privkey),
				contents: unsigned_channel_update.clone()
			};
			match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Test that announcements with excess data won't be returned
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(short_channel_id, 1);
		assert_eq!(channels_with_announcements.len(), 1);
		if let Some(channel_announcements) = channels_with_announcements.first() {
			let &(_, ref update_1, ref update_2) = channel_announcements;
			assert_eq!(update_1, &None);
			assert_eq!(update_2, &None);
		} else {
			panic!();
		}

		// Further starting point have no channels after it
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(short_channel_id + 1000, 1);
		assert_eq!(channels_with_announcements.len(), 0);
	}

	#[test]
	fn getting_next_node_announcements() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let short_channel_id = 1;
		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// No nodes yet.
		let next_announcements = net_graph_msg_handler.get_next_node_announcements(None, 10);
		assert_eq!(next_announcements.len(), 0);

		{
			// Announce a channel to add 2 nodes
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash,
				short_channel_id,
				node_id_1,
				node_id_2,
				bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
				bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
				excess_data: Vec::new(),
			};

			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_channel_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
				node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
				bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
				bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
				contents: unsigned_announcement.clone(),
			};
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}


		// Nodes were never announced
		let next_announcements = net_graph_msg_handler.get_next_node_announcements(None, 3);
		assert_eq!(next_announcements.len(), 0);

		{
			let mut unsigned_announcement = UnsignedNodeAnnouncement {
				features: NodeFeatures::known(),
				timestamp: 1000,
				node_id: node_id_1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				excess_address_data: Vec::new(),
				excess_data: Vec::new(),
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_announcement = NodeAnnouncement {
				signature: secp_ctx.sign(&msghash, node_1_privkey),
				contents: unsigned_announcement.clone()
			};
			match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

			unsigned_announcement.node_id = node_id_2;
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_announcement = NodeAnnouncement {
				signature: secp_ctx.sign(&msghash, node_2_privkey),
				contents: unsigned_announcement.clone()
			};

			match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		let next_announcements = net_graph_msg_handler.get_next_node_announcements(None, 3);
		assert_eq!(next_announcements.len(), 2);

		// Skip the first node.
		let next_announcements = net_graph_msg_handler.get_next_node_announcements(Some(&node_id_1), 2);
		assert_eq!(next_announcements.len(), 1);

		{
			// Later announcement which should not be relayed (excess data) prevent us from sharing a node
			let unsigned_announcement = UnsignedNodeAnnouncement {
				features: NodeFeatures::known(),
				timestamp: 1010,
				node_id: node_id_2,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				excess_address_data: Vec::new(),
				excess_data: [1; 3].to_vec(),
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let valid_announcement = NodeAnnouncement {
				signature: secp_ctx.sign(&msghash, node_2_privkey),
				contents: unsigned_announcement.clone()
			};
			match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
				Ok(res) => assert!(!res),
				Err(_) => panic!()
			};
		}

		let next_announcements = net_graph_msg_handler.get_next_node_announcements(Some(&node_id_1), 2);
		assert_eq!(next_announcements.len(), 0);
	}

	#[test]
	fn network_graph_serialization() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		// Announce a channel to add a corresponding node.
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let unsigned_announcement = UnsignedChannelAnnouncement {
			features: ChannelFeatures::known(),
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 0,
			node_id_1,
			node_id_2,
			bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, node_1_btckey),
			bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, node_2_btckey),
			excess_data: Vec::new(),
		};

		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};


		let node_id = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let unsigned_announcement = UnsignedNodeAnnouncement {
			features: NodeFeatures::known(),
			timestamp: 100,
			node_id,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_1_privkey),
			contents: unsigned_announcement.clone()
		};

		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};

		let network = net_graph_msg_handler.network_graph.write().unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		assert!(!network.get_nodes().is_empty());
		assert!(!network.get_channels().is_empty());
		network.write(&mut w).unwrap();
		assert!(<NetworkGraph>::read(&mut ::std::io::Cursor::new(&w.0)).unwrap() == *network);
	}

	#[test]
	fn sending_query_channel_range() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_privkey_2 = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_privkey_2);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let first_blocknum = 0;
		let number_of_blocks = 0xffff_ffff;

		// When no active query exists for the node, it should send a query message and generate a task
		{
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, first_blocknum, number_of_blocks);
			assert!(result.is_ok());

			// It should create a task for the query
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().contains_key(&node_id_1));

			// It should send a query_channel_range message with the correct information
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendChannelRangeQuery{ node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.first_blocknum, first_blocknum);
					assert_eq!(msg.number_of_blocks, number_of_blocks);
				},
				_ => panic!("Expected MessageSendEvent::SendChannelRangeQuery")
			};
		}

		// When an active query exists for the node, when there is a subsequent query request, it
		// should fail to initiate a new query
		{
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, first_blocknum, number_of_blocks);
			assert_eq!(result.is_err(), true);
		}

		// When no active query exists for a different node, it should send a query message
		{
			let result = net_graph_msg_handler.query_channel_range(&node_id_2, chain_hash, first_blocknum, number_of_blocks);
			assert_eq!(result.is_ok(), true);

			// It should create a task for the query
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().contains_key(&node_id_2));

			// It should send a query_channel_message with the correct information
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendChannelRangeQuery{ node_id, msg } => {
					assert_eq!(node_id, &node_id_2);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.first_blocknum, first_blocknum);
					assert_eq!(msg.number_of_blocks, number_of_blocks);
				},
				_ => panic!("Expected MessageSendEvent::SendChannelRangeQuery")
			};
		}
	}

	#[test]
	fn sending_query_short_channel_ids() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// The first query should send the batch of scids to the peer
		{
			let short_channel_ids: Vec<u64> = vec![0, 1, 2];
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id_1, chain_hash, short_channel_ids.clone());
			assert!(result.is_ok());

			// Validate that we have enqueued a send message event and that it contains the correct information
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery{ node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, short_channel_ids);
				},
				_ => panic!("Expected MessageSendEvent::SendShortIdsQuery")
			};
		}

		// Subsequent queries for scids should enqueue them to be sent in the next batch which will
		// be sent when a reply_short_channel_ids_end message is handled.
		{
			let short_channel_ids: Vec<u64> = vec![3, 4, 5];
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id_1, chain_hash, short_channel_ids.clone());
			assert!(result.is_ok());

			// Validate that we have not enqueued another send message event yet
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 0);

			// Validate the task has the queued scids
			assert_eq!(
				net_graph_msg_handler.scid_query_tasks.lock().unwrap().get(&node_id_1).unwrap().short_channel_ids,
				short_channel_ids
			);
		}
	}

	#[test]
	fn handling_reply_channel_range() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// Test receipt of an unknown reply message. We expect an error
		{
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 1050,
				short_channel_ids: vec![
					0x0003e8_000000_0000, // 1000x0x0
					0x0003e9_000000_0000, // 1001x0x0
					0x0003f0_000000_0000  // 1008x0x0
				],
			});
			assert!(result.is_err());
		}

		// Test receipt of a single reply_channel_range that exactly matches the queried range.
		// It sends a query_short_channel_ids with the returned scids and removes the pending task
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle a single successful reply that matches the queried channel range
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 100,
				short_channel_ids: vec![
					0x0003e8_000000_0000, // 1000x0x0
					0x0003e9_000000_0000, // 1001x0x0
					0x0003f0_000000_0000  // 1008x0x0
				],
			});
			assert!(result.is_ok());

			// The query is now complete, so we expect the task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());

			// We expect to emit a query_short_channel_ids message with scids in our query range
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, vec![0x0003e8_000000_0000,0x0003e9_000000_0000,0x0003f0_000000_0000]);
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// Clean up scid_task
			net_graph_msg_handler.scid_query_tasks.lock().unwrap().clear();
		}

		// Test receipt of a single reply_channel_range for a query that has a u32 overflow. We expect
		// it sends a query_short_channel_ids with the returned scids and removes the pending task.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 0xffff_ffff);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle a single successful reply that matches the queried channel range
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 0xffff_ffff,
				short_channel_ids: vec![
					0x0003e8_000000_0000, // 1000x0x0
					0x0003e9_000000_0000, // 1001x0x0
					0x0003f0_000000_0000  // 1008x0x0
				],
			});
			assert!(result.is_ok());

			// The query is now complete, so we expect the task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());

			// We expect to emit a query_short_channel_ids message with scids in our query range
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, vec![0x0003e8_000000_0000,0x0003e9_000000_0000,0x0003f0_000000_0000]);
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// Clean up scid_task
			net_graph_msg_handler.scid_query_tasks.lock().unwrap().clear();
		}

		// Test receipt of a single reply that encompasses the queried channel range. This is allowed
		// since a reply must contain at least part of the query range. Receipt of the reply should
		// send a query_short_channel_ids message with scids filtered to the query range and remove
		// the pending task.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle a single successful reply that encompasses the queried channel range
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 0,
				number_of_blocks: 2000,
				short_channel_ids: vec![
					0x0003e0_000000_0000, // 992x0x0
					0x0003e8_000000_0000, // 1000x0x0
					0x0003e9_000000_0000, // 1001x0x0
					0x0003f0_000000_0000, // 1008x0x0
					0x00044c_000000_0000, // 1100x0x0
					0x0006e0_000000_0000, // 1760x0x0
				],
			});
			assert!(result.is_ok());

			// The query is now complete, so we expect the task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());

			// We expect to emit a query_short_channel_ids message with scids filtered to those
			// within the original query range.
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, vec![0x0003e8_000000_0000,0x0003e9_000000_0000,0x0003f0_000000_0000]);
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// Clean up scid_task
			net_graph_msg_handler.scid_query_tasks.lock().unwrap().clear();
		}

		// Test receipt of multiple reply messages for a single query. This happens when the number
		// of scids in the query range exceeds the size limits of a single reply message. We expect
		// to initiate a query_short_channel_ids for the first batch of scids and we enqueue the
		// remaining scids for later processing. We remove the range query task after receipt of all
		// reply messages.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the first reply message
			let reply_1_scids =  vec![
				0x0003e8_000000_0000, // 1000x0x0
				0x0003e9_000000_0000, // 1001x0x0
				0x000419_000000_0000, // 1049x0x0
			];
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 50,
				short_channel_ids: reply_1_scids.clone(),
			});
			assert!(result.is_ok());

			// Handle the next reply in the sequence, which must start at the previous message's
			// first_blocknum plus number_of_blocks. The scids in this reply will be queued.
			let reply_2_scids = vec![
				0x00041a_000000_0000, // 1050x0x0
				0x000432_000000_0000, // 1074x0x0
			];
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1050,
				number_of_blocks: 25,
				short_channel_ids: reply_2_scids.clone(),
			});
			assert!(result.is_ok());

			// Handle the final reply in the sequence, which must meet or exceed the initial query's
			// first_blocknum plus number_of_blocks. The scids in this reply will be queued.
			let reply_3_scids = vec![
				0x000433_000000_0000, // 1075x0x0
				0x00044b_000000_0000, // 1099x0x0
			];
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1075,
				number_of_blocks: 25,
				short_channel_ids: reply_3_scids.clone(),
			});
			assert!(result.is_ok());

			// After the final reply we expect the query task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());

			// We expect to emit a query_short_channel_ids message with the accumulated scids that
			// match the queried channel range.
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, [reply_1_scids, reply_2_scids, reply_3_scids].concat());
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// Clean up scid_task
			net_graph_msg_handler.scid_query_tasks.lock().unwrap().clear();
		}

		// Test receipt of a sequence of replies with a valid first reply and a second reply that
		// resumes on the same block as the first reply. The spec requires a subsequent
		// first_blocknum to equal the prior first_blocknum plus number_of_blocks, however
		// due to discrepancies in implementation we must loosen this restriction.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the first reply message
			let reply_1_scids = vec![
				0x0003e8_000000_0000, // 1000x0x0
				0x0003e9_000000_0000, // 1001x0x0
				0x000419_000000_0000, // 1049x0x0
			];
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 50,
				short_channel_ids: reply_1_scids.clone(),
			});
			assert!(result.is_ok());

			// Handle the next reply in the sequence, which is non-spec but resumes on the last block
			// of the first message.
			let reply_2_scids = vec![
				0x000419_000001_0000, // 1049x1x0
				0x00041a_000000_0000, // 1050x0x0
				0x000432_000000_0000, // 1074x0x0
			];
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1049,
				number_of_blocks: 51,
				short_channel_ids: reply_2_scids.clone(),
			});
			assert!(result.is_ok());

			// After the final reply we expect the query task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());

			// We expect to emit a query_short_channel_ids message with the accumulated scids that
			// match the queried channel range
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, [reply_1_scids, reply_2_scids].concat());
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// Clean up scid_task
			net_graph_msg_handler.scid_query_tasks.lock().unwrap().clear();
		}

		// Test receipt of reply with a chain_hash that does not match the query. We expect to return
		// an error and to remove the query task.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the reply with a mismatched chain_hash. We expect IgnoreError result and the
			// task should be removed.
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash: genesis_block(Network::Bitcoin).header.block_hash(),
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 1050,
				short_channel_ids: vec![0x0003e8_000000_0000,0x0003e9_000000_0000,0x0003f0_000000_0000],
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Received reply_channel_range with invalid chain_hash");
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a reply that indicates the remote node does not maintain up-to-date
		// information for the chain_hash. Because of discrepancies in implementation we use
		// full_information=false and short_channel_ids=[] as the signal. We should expect an error
		// and the task should be removed.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the reply indicating the peer was unable to fulfill our request.
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: false,
				first_blocknum: 1000,
				number_of_blocks: 100,
				short_channel_ids: vec![],
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Received reply_channel_range with no information available");
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a reply that has a first_blocknum that is above the first_blocknum
		// requested in our query. The reply must contain the queried block range. We expect an
		// error result and the task should be removed.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the reply that has a first_blocknum above the query's first_blocknum
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1001,
				number_of_blocks: 100,
				short_channel_ids: vec![],
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Failing reply_channel_range with invalid first_blocknum");
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a first reply that does not overlap the query range at all. The first message
		// must have some overlap with the query. We expect an error result and the task should
		// be removed.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle a reply that contains a block range that precedes the queried block range
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 0,
				number_of_blocks: 1000,
				short_channel_ids: vec![],
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Failing reply_channel_range with non-overlapping first reply");
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a sequence of replies with a valid first reply and a second reply that is
		// non-sequential. The spec requires a subsequent first_blocknum to equal the prior
		// first_blocknum plus number_of_blocks. We expect an IgnoreError result and the task should
		// be removed.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 100);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the first reply
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1000,
				number_of_blocks: 50,
				short_channel_ids: vec![0x0003e8_000000_0000,0x0003e9_000000_0000,0x0003f0_000000_0000],
			});
			assert!(result.is_ok());

			// Handle the second reply which does not start at the proper first_blocknum. We expect
			// to return an error and remove the task.
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
				chain_hash,
				full_information: true,
				first_blocknum: 1051,
				number_of_blocks: 50,
				short_channel_ids: vec![0x0003f1_000000_0000,0x0003f2_000000_0000],
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Failing reply_channel_range with invalid sequence");
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of too many reply messages. We expect an IgnoreError result and the task should
		// be removed.
		{
			// Initiate a channel range query to create a query task
			let result = net_graph_msg_handler.query_channel_range(&node_id_1, chain_hash, 1000, 0xffff_ffff);
			assert!(result.is_ok());

			// Clear the SendRangeQuery event
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle a sequence of replies that will fail once the max number of reply has been exceeded.
			for block in 1000..=1000 + super::MAX_REPLY_CHANNEL_RANGE_PER_QUERY + 10 {
				let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, &ReplyChannelRange {
					chain_hash,
					full_information: true,
					first_blocknum: block as u32,
					number_of_blocks: 1,
					short_channel_ids: vec![(block as u64) << 40],
				});
				if block <= 1000 + super::MAX_REPLY_CHANNEL_RANGE_PER_QUERY {
					assert!(result.is_ok());
				} else if block == 1001 + super::MAX_REPLY_CHANNEL_RANGE_PER_QUERY {
					assert!(result.is_err());
					assert_eq!(result.err().unwrap().err, "Failing reply_channel_range due to excessive messages");
				} else {
					assert!(result.is_err());
					assert_eq!(result.err().unwrap().err, "Received unknown reply_channel_range message");
				}
			}

			// Expect the task to be removed
			assert!(net_graph_msg_handler.chan_range_query_tasks.lock().unwrap().is_empty());
		}
	}

	#[test]
	fn handling_reply_short_channel_ids() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// Test receipt of a reply when no query exists. We expect an error to be returned
		{
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: true,
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Unknown reply_short_channel_ids_end message");
		}

		// Test receipt of a reply that is for a different chain_hash. We expect an error and the task
		// should be removed.
		{
			// Initiate a query to create a pending query task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003e8_000000_0000]);
			assert!(result.is_ok());

			// Process reply with incorrect chain_hash
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash: genesis_block(Network::Bitcoin).header.block_hash(),
				full_information: true,
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Received reply_short_channel_ids_end with incorrect chain_hash");

			// Expect the task to be removed
			assert!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a reply that indicates the peer does not maintain up-to-date information
		// for the chain_hash requested in the query. We expect an error and task should be removed.
		{
			// Initiate a query to create a pending query task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003e8_000000_0000]);
			assert!(result.is_ok());

			// Process failed reply
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: false,
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Received reply_short_channel_ids_end with no information");

			// Expect the task to be removed
			assert!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a successful reply when there are no additional scids to query. We expect
		// the task to be removed.
		{
			// Initiate a query to create a pending query task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003e8_000000_0000]);
			assert!(result.is_ok());

			// Process success reply
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: true,
			});
			assert!(result.is_ok());

			// Expect the task to be removed
			assert!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().is_empty());
		}

		// Test receipt of a successful reply when there are additional scids to query. We expect
		// additional queries to be sent until the task can be removed.
		{
			// Initiate a query to create a pending query task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003e8_000000_0000]);
			assert!(result.is_ok());

			// Initiate a second query to add pending scids to the task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003e9_000000_0000]);
			assert!(result.is_ok());
			assert_eq!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().get(&node_id).unwrap().short_channel_ids, vec![0x0003e9_000000_0000]);

			// Initiate a third query to add pending scids to the task
			let result = net_graph_msg_handler.query_short_channel_ids(&node_id, chain_hash, vec![0x0003f0_000000_0000]);
			assert!(result.is_ok());
			assert_eq!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().get(&node_id).unwrap().short_channel_ids, vec![0x0003e9_000000_0000, 0x0003f0_000000_0000]);

			// Clear all of the pending send events
			net_graph_msg_handler.get_and_clear_pending_msg_events();

			// Handle the first successful reply, which will send the next batch of scids in a new query
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: true,
			});
			assert!(result.is_ok());

			// We expect the second batch to be sent in an event
			let expected_node_id = &node_id;
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, expected_node_id);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, vec![0x0003e9_000000_0000, 0x0003f0_000000_0000]);
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}

			// We expect the scids to be cleared from the task
			assert_eq!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().get(&node_id).unwrap().short_channel_ids.len(), 0);

			// Handle the second successful reply
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, &ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: true,
			});
			assert!(result.is_ok());

			// We expect the task should be removed
			assert!(net_graph_msg_handler.scid_query_tasks.lock().unwrap().is_empty());
		}
	}

	#[test]
	fn handling_query_channel_range() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		let result = net_graph_msg_handler.handle_query_channel_range(&node_id, &QueryChannelRange {
			chain_hash,
			first_blocknum: 0,
			number_of_blocks: 0xffff_ffff,
		});
		assert!(result.is_err());
	}

	#[test]
	fn handling_query_short_channel_ids() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		let result = net_graph_msg_handler.handle_query_short_channel_ids(&node_id, &QueryShortChannelIds {
			chain_hash,
			short_channel_ids: vec![0x0003e8_000000_0000],
		});
		assert!(result.is_err());
	}
}
