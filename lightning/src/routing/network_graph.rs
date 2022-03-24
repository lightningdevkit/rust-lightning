// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The top-level network map tracking logic lives here.

use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
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
use ln::msgs::{DecodeError, ErrorAction, Init, LightningError, RoutingMessageHandler, NetAddress, MAX_VALUE_MSAT};
use ln::msgs::{ChannelAnnouncement, ChannelUpdate, NodeAnnouncement, OptionalField, GossipTimestampFilter};
use ln::msgs::{QueryChannelRange, ReplyChannelRange, QueryShortChannelIds, ReplyShortChannelIdsEnd};
use ln::msgs;
use util::ser::{Writeable, Readable, Writer};
use util::logger::{Logger, Level};
use util::events::{Event, EventHandler, MessageSendEvent, MessageSendEventsProvider};
use util::scid_utils::{block_from_scid, scid_from_parts, MAX_SCID_BLOCK};

use io;
use prelude::*;
use alloc::collections::{BTreeMap, btree_map::Entry as BtreeEntry};
use core::{cmp, fmt};
use sync::{RwLock, RwLockReadGuard};
use core::sync::atomic::{AtomicUsize, Ordering};
use sync::Mutex;
use core::ops::Deref;
use bitcoin::hashes::hex::ToHex;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// We remove stale channel directional info two weeks after the last update, per BOLT 7's
/// suggestion.
const STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS: u64 = 60 * 60 * 24 * 14;

/// The maximum number of extra bytes which we do not understand in a gossip message before we will
/// refuse to relay the message.
const MAX_EXCESS_BYTES_FOR_RELAY: usize = 1024;

/// Maximum number of short_channel_ids that will be encoded in one gossip reply message.
/// This value ensures a reply fits within the 65k payload limit and is consistent with other implementations.
const MAX_SCIDS_PER_REPLY: usize = 8000;

/// Represents the compressed public key of a node
#[derive(Clone, Copy)]
pub struct NodeId([u8; PUBLIC_KEY_SIZE]);

impl NodeId {
	/// Create a new NodeId from a public key
	pub fn from_pubkey(pubkey: &PublicKey) -> Self {
		NodeId(pubkey.serialize())
	}
	
	/// Get the public key slice from this NodeId
	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Debug for NodeId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "NodeId({})", log_bytes!(self.0))
	}
}

impl core::hash::Hash for NodeId {
	fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
		self.0.hash(hasher);
	}
}

impl Eq for NodeId {}

impl PartialEq for NodeId {
	fn eq(&self, other: &Self) -> bool {
		self.0[..] == other.0[..]
	}
}

impl cmp::PartialOrd for NodeId {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for NodeId {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.0[..].cmp(&other.0[..])
	}
}

impl Writeable for NodeId {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&self.0)?;
		Ok(())
	}
}

impl Readable for NodeId {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut buf = [0; PUBLIC_KEY_SIZE];
		reader.read_exact(&mut buf)?;
		Ok(Self(buf))
	}
}

/// Represents the network as nodes and channels between them
pub struct NetworkGraph {
	genesis_hash: BlockHash,
	// Lock order: channels -> nodes
	channels: RwLock<BTreeMap<u64, ChannelInfo>>,
	nodes: RwLock<BTreeMap<NodeId, NodeInfo>>,
}

impl Clone for NetworkGraph {
	fn clone(&self) -> Self {
		let channels = self.channels.read().unwrap();
		let nodes = self.nodes.read().unwrap();
		Self {
			genesis_hash: self.genesis_hash.clone(),
			channels: RwLock::new(channels.clone()),
			nodes: RwLock::new(nodes.clone()),
		}
	}
}

/// A read-only view of [`NetworkGraph`].
pub struct ReadOnlyNetworkGraph<'a> {
	channels: RwLockReadGuard<'a, BTreeMap<u64, ChannelInfo>>,
	nodes: RwLockReadGuard<'a, BTreeMap<NodeId, NodeInfo>>,
}

/// Update to the [`NetworkGraph`] based on payment failure information conveyed via the Onion
/// return packet by a node along the route. See [BOLT #4] for details.
///
/// [BOLT #4]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
#[derive(Clone, Debug, PartialEq)]
pub enum NetworkUpdate {
	/// An error indicating a `channel_update` messages should be applied via
	/// [`NetworkGraph::update_channel`].
	ChannelUpdateMessage {
		/// The update to apply via [`NetworkGraph::update_channel`].
		msg: ChannelUpdate,
	},
	/// An error indicating only that a channel has been closed, which should be applied via
	/// [`NetworkGraph::close_channel_from_update`].
	ChannelClosed {
		/// The short channel id of the closed channel.
		short_channel_id: u64,
		/// Whether the channel should be permanently removed or temporarily disabled until a new
		/// `channel_update` message is received.
		is_permanent: bool,
	},
	/// An error indicating only that a node has failed, which should be applied via
	/// [`NetworkGraph::fail_node`].
	NodeFailure {
		/// The node id of the failed node.
		node_id: PublicKey,
		/// Whether the node should be permanently removed from consideration or can be restored
		/// when a new `channel_update` message is received.
		is_permanent: bool,
	}
}

impl_writeable_tlv_based_enum_upgradable!(NetworkUpdate,
	(0, ChannelUpdateMessage) => {
		(0, msg, required),
	},
	(2, ChannelClosed) => {
		(0, short_channel_id, required),
		(2, is_permanent, required),
	},
	(4, NodeFailure) => {
		(0, node_id, required),
		(2, is_permanent, required),
	},
);

impl<G: Deref<Target=NetworkGraph>, C: Deref, L: Deref> EventHandler for NetGraphMsgHandler<G, C, L>
where C::Target: chain::Access, L::Target: Logger {
	fn handle_event(&self, event: &Event) {
		if let Event::PaymentPathFailed { payment_hash: _, rejected_by_dest: _, network_update, .. } = event {
			if let Some(network_update) = network_update {
				self.handle_network_update(network_update);
			}
		}
	}
}

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
///
/// Serves as an [`EventHandler`] for applying updates from [`Event::PaymentPathFailed`] to the
/// [`NetworkGraph`].
pub struct NetGraphMsgHandler<G: Deref<Target=NetworkGraph>, C: Deref, L: Deref>
where C::Target: chain::Access, L::Target: Logger
{
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	network_graph: G,
	chain_access: Option<C>,
	full_syncs_requested: AtomicUsize,
	pending_events: Mutex<Vec<MessageSendEvent>>,
	logger: L,
}

impl<G: Deref<Target=NetworkGraph>, C: Deref, L: Deref> NetGraphMsgHandler<G, C, L>
where C::Target: chain::Access, L::Target: Logger
{
	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming an existing Network Graph.
	/// Chain monitor is used to make sure announced channels exist on-chain,
	/// channel data is correct, and that the announcement is signed with
	/// channel owners' keys.
	pub fn new(network_graph: G, chain_access: Option<C>, logger: L) -> Self {
		NetGraphMsgHandler {
			secp_ctx: Secp256k1::verification_only(),
			network_graph,
			full_syncs_requested: AtomicUsize::new(0),
			chain_access,
			pending_events: Mutex::new(vec![]),
			logger,
		}
	}

	/// Adds a provider used to check new announcements. Does not affect
	/// existing announcements unless they are updated.
	/// Add, update or remove the provider would replace the current one.
	pub fn add_chain_access(&mut self, chain_access: Option<C>) {
		self.chain_access = chain_access;
	}

	/// Gets a reference to the underlying [`NetworkGraph`] which was provided in
	/// [`NetGraphMsgHandler::new`].
	///
	/// (C-not exported) as bindings don't support a reference-to-a-reference yet
	pub fn network_graph(&self) -> &G {
		&self.network_graph
	}

	/// Returns true when a full routing table sync should be performed with a peer.
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

	/// Applies changes to the [`NetworkGraph`] from the given update.
	fn handle_network_update(&self, update: &NetworkUpdate) {
		match *update {
			NetworkUpdate::ChannelUpdateMessage { ref msg } => {
				let short_channel_id = msg.contents.short_channel_id;
				let is_enabled = msg.contents.flags & (1 << 1) != (1 << 1);
				let status = if is_enabled { "enabled" } else { "disabled" };
				log_debug!(self.logger, "Updating channel with channel_update from a payment failure. Channel {} is {}.", short_channel_id, status);
				let _ = self.network_graph.update_channel(msg, &self.secp_ctx);
			},
			NetworkUpdate::ChannelClosed { short_channel_id, is_permanent } => {
				let action = if is_permanent { "Removing" } else { "Disabling" };
				log_debug!(self.logger, "{} channel graph entry for {} due to a payment failure.", action, short_channel_id);
				self.network_graph.close_channel_from_update(short_channel_id, is_permanent);
			},
			NetworkUpdate::NodeFailure { ref node_id, is_permanent } => {
				let action = if is_permanent { "Removing" } else { "Disabling" };
				log_debug!(self.logger, "{} node graph entry for {} due to a payment failure.", action, node_id);
				self.network_graph.fail_node(node_id, is_permanent);
			},
		}
	}
}

macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr, $msg_type: expr ) => {
		match $secp_ctx.verify($msg, $sig, $pubkey) {
			Ok(_) => {},
			Err(_) => {
				return Err(LightningError {
					err: format!("Invalid signature on {} message", $msg_type),
					action: ErrorAction::SendWarningMessage {
						msg: msgs::WarningMessage {
							channel_id: [0; 32],
							data: format!("Invalid signature on {} message", $msg_type),
						},
						log_level: Level::Trace,
					},
				});
			},
		}
	};
}

impl<G: Deref<Target=NetworkGraph>, C: Deref, L: Deref> RoutingMessageHandler for NetGraphMsgHandler<G, C, L>
where C::Target: chain::Access, L::Target: Logger
{
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_node_from_announcement(msg, &self.secp_ctx)?;
		Ok(msg.contents.excess_data.len() <=  MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_data.len() + msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_channel_from_announcement(msg, &self.chain_access, &self.secp_ctx)?;
		log_gossip!(self.logger, "Added channel_announcement for {}{}", msg.contents.short_channel_id, if !msg.contents.excess_data.is_empty() { " with excess uninterpreted data!" } else { "" });
		Ok(msg.contents.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
		self.network_graph.update_channel(msg, &self.secp_ctx)?;
		Ok(msg.contents.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)> {
		let mut result = Vec::with_capacity(batch_amount as usize);
		let channels = self.network_graph.channels.read().unwrap();
		let mut iter = channels.range(starting_point..);
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
		let mut result = Vec::with_capacity(batch_amount as usize);
		let nodes = self.network_graph.nodes.read().unwrap();
		let mut iter = if let Some(pubkey) = starting_point {
				let mut iter = nodes.range(NodeId::from_pubkey(pubkey)..);
				iter.next();
				iter
			} else {
				nodes.range::<NodeId, _>(..)
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

	/// Initiates a stateless sync of routing gossip information with a peer
	/// using gossip_queries. The default strategy used by this implementation
	/// is to sync the full block range with several peers.
	///
	/// We should expect one or more reply_channel_range messages in response
	/// to our query_channel_range. Each reply will enqueue a query_scid message
	/// to request gossip messages for each channel. The sync is considered complete
	/// when the final reply_scids_end message is received, though we are not
	/// tracking this directly.
	fn peer_connected(&self, their_node_id: &PublicKey, init_msg: &Init) {
		// We will only perform a sync with peers that support gossip_queries.
		if !init_msg.features.supports_gossip_queries() {
			return ();
		}

		// Send a gossip_timestamp_filter to enable gossip message receipt. Note that we have to
		// use a "all timestamps" filter as sending the current timestamp would result in missing
		// gossip messages that are simply sent late. We could calculate the intended filter time
		// by looking at the current time and subtracting two weeks (before which we'll reject
		// messages), but there's not a lot of reason to bother - our peers should be discarding
		// the same messages.
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(MessageSendEvent::SendGossipTimestampFilter {
			node_id: their_node_id.clone(),
			msg: GossipTimestampFilter {
				chain_hash: self.network_graph.genesis_hash,
				first_timestamp: 0,
				timestamp_range: u32::max_value(),
			},
		});

		// Check if we need to perform a full synchronization with this peer
		if !self.should_request_full_sync(&their_node_id) {
			return ();
		}

		let first_blocknum = 0;
		let number_of_blocks = 0xffffffff;
		log_debug!(self.logger, "Sending query_channel_range peer={}, first_blocknum={}, number_of_blocks={}", log_pubkey!(their_node_id), first_blocknum, number_of_blocks);
		pending_events.push(MessageSendEvent::SendChannelRangeQuery {
			node_id: their_node_id.clone(),
			msg: QueryChannelRange {
				chain_hash: self.network_graph.genesis_hash,
				first_blocknum,
				number_of_blocks,
			},
		});
	}

	/// Statelessly processes a reply to a channel range query by immediately
	/// sending an SCID query with SCIDs in the reply. To keep this handler
	/// stateless, it does not validate the sequencing of replies for multi-
	/// reply ranges. It does not validate whether the reply(ies) cover the
	/// queried range. It also does not filter SCIDs to only those in the
	/// original query range. We also do not validate that the chain_hash
	/// matches the chain_hash of the NetworkGraph. Any chan_ann message that
	/// does not match our chain_hash will be rejected when the announcement is
	/// processed.
	fn handle_reply_channel_range(&self, their_node_id: &PublicKey, msg: ReplyChannelRange) -> Result<(), LightningError> {
		log_debug!(self.logger, "Handling reply_channel_range peer={}, first_blocknum={}, number_of_blocks={}, sync_complete={}, scids={}", log_pubkey!(their_node_id), msg.first_blocknum, msg.number_of_blocks, msg.sync_complete, msg.short_channel_ids.len(),);

		log_debug!(self.logger, "Sending query_short_channel_ids peer={}, batch_size={}", log_pubkey!(their_node_id), msg.short_channel_ids.len());
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(MessageSendEvent::SendShortIdsQuery {
			node_id: their_node_id.clone(),
			msg: QueryShortChannelIds {
				chain_hash: msg.chain_hash,
				short_channel_ids: msg.short_channel_ids,
			}
		});

		Ok(())
	}

	/// When an SCID query is initiated the remote peer will begin streaming
	/// gossip messages. In the event of a failure, we may have received
	/// some channel information. Before trying with another peer, the
	/// caller should update its set of SCIDs that need to be queried.
	fn handle_reply_short_channel_ids_end(&self, their_node_id: &PublicKey, msg: ReplyShortChannelIdsEnd) -> Result<(), LightningError> {
		log_debug!(self.logger, "Handling reply_short_channel_ids_end peer={}, full_information={}", log_pubkey!(their_node_id), msg.full_information);

		// If the remote node does not have up-to-date information for the
		// chain_hash they will set full_information=false. We can fail
		// the result and try again with a different peer.
		if !msg.full_information {
			return Err(LightningError {
				err: String::from("Received reply_short_channel_ids_end with no information"),
				action: ErrorAction::IgnoreError
			});
		}

		Ok(())
	}

	/// Processes a query from a peer by finding announced/public channels whose funding UTXOs
	/// are in the specified block range. Due to message size limits, large range
	/// queries may result in several reply messages. This implementation enqueues
	/// all reply messages into pending events. Each message will allocate just under 65KiB. A full
	/// sync of the public routing table with 128k channels will generated 16 messages and allocate ~1MB.
	/// Logic can be changed to reduce allocation if/when a full sync of the routing table impacts
	/// memory constrained systems.
	fn handle_query_channel_range(&self, their_node_id: &PublicKey, msg: QueryChannelRange) -> Result<(), LightningError> {
		log_debug!(self.logger, "Handling query_channel_range peer={}, first_blocknum={}, number_of_blocks={}", log_pubkey!(their_node_id), msg.first_blocknum, msg.number_of_blocks);

		let inclusive_start_scid = scid_from_parts(msg.first_blocknum as u64, 0, 0);

		// We might receive valid queries with end_blocknum that would overflow SCID conversion.
		// If so, we manually cap the ending block to avoid this overflow.
		let exclusive_end_scid = scid_from_parts(cmp::min(msg.end_blocknum() as u64, MAX_SCID_BLOCK), 0, 0);

		// Per spec, we must reply to a query. Send an empty message when things are invalid.
		if msg.chain_hash != self.network_graph.genesis_hash || inclusive_start_scid.is_err() || exclusive_end_scid.is_err() || msg.number_of_blocks == 0 {
			let mut pending_events = self.pending_events.lock().unwrap();
			pending_events.push(MessageSendEvent::SendReplyChannelRange {
				node_id: their_node_id.clone(),
				msg: ReplyChannelRange {
					chain_hash: msg.chain_hash.clone(),
					first_blocknum: msg.first_blocknum,
					number_of_blocks: msg.number_of_blocks,
					sync_complete: true,
					short_channel_ids: vec![],
				}
			});
			return Err(LightningError {
				err: String::from("query_channel_range could not be processed"),
				action: ErrorAction::IgnoreError,
			});
		}

		// Creates channel batches. We are not checking if the channel is routable
		// (has at least one update). A peer may still want to know the channel
		// exists even if its not yet routable.
		let mut batches: Vec<Vec<u64>> = vec![Vec::with_capacity(MAX_SCIDS_PER_REPLY)];
		let channels = self.network_graph.channels.read().unwrap();
		for (_, ref chan) in channels.range(inclusive_start_scid.unwrap()..exclusive_end_scid.unwrap()) {
			if let Some(chan_announcement) = &chan.announcement_message {
				// Construct a new batch if last one is full
				if batches.last().unwrap().len() == batches.last().unwrap().capacity() {
					batches.push(Vec::with_capacity(MAX_SCIDS_PER_REPLY));
				}

				let batch = batches.last_mut().unwrap();
				batch.push(chan_announcement.contents.short_channel_id);
			}
		}
		drop(channels);

		let mut pending_events = self.pending_events.lock().unwrap();
		let batch_count = batches.len();
		let mut prev_batch_endblock = msg.first_blocknum;
		for (batch_index, batch) in batches.into_iter().enumerate() {
			// Per spec, the initial `first_blocknum` needs to be <= the query's `first_blocknum`
			// and subsequent `first_blocknum`s must be >= the prior reply's `first_blocknum`.
			//
			// Additionally, c-lightning versions < 0.10 require that the `first_blocknum` of each
			// reply is >= the previous reply's `first_blocknum` and either exactly the previous
			// reply's `first_blocknum + number_of_blocks` or exactly one greater. This is a
			// significant diversion from the requirements set by the spec, and, in case of blocks
			// with no channel opens (e.g. empty blocks), requires that we use the previous value
			// and *not* derive the first_blocknum from the actual first block of the reply.
			let first_blocknum = prev_batch_endblock;

			// Each message carries the number of blocks (from the `first_blocknum`) its contents
			// fit in. Though there is no requirement that we use exactly the number of blocks its
			// contents are from, except for the bogus requirements c-lightning enforces, above.
			//
			// Per spec, the last end block (ie `first_blocknum + number_of_blocks`) needs to be
			// >= the query's end block. Thus, for the last reply, we calculate the difference
			// between the query's end block and the start of the reply.
			//
			// Overflow safe since end_blocknum=msg.first_block_num+msg.number_of_blocks and
			// first_blocknum will be either msg.first_blocknum or a higher block height.
			let (sync_complete, number_of_blocks) = if batch_index == batch_count-1 {
				(true, msg.end_blocknum() - first_blocknum)
			}
			// Prior replies should use the number of blocks that fit into the reply. Overflow
			// safe since first_blocknum is always <= last SCID's block.
			else {
				(false, block_from_scid(batch.last().unwrap()) - first_blocknum)
			};

			prev_batch_endblock = first_blocknum + number_of_blocks;

			pending_events.push(MessageSendEvent::SendReplyChannelRange {
				node_id: their_node_id.clone(),
				msg: ReplyChannelRange {
					chain_hash: msg.chain_hash.clone(),
					first_blocknum,
					number_of_blocks,
					sync_complete,
					short_channel_ids: batch,
				}
			});
		}

		Ok(())
	}

	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: QueryShortChannelIds) -> Result<(), LightningError> {
		// TODO
		Err(LightningError {
			err: String::from("Not implemented"),
			action: ErrorAction::IgnoreError,
		})
	}
}

impl<G: Deref<Target=NetworkGraph>, C: Deref, L: Deref> MessageSendEventsProvider for NetGraphMsgHandler<G, C, L>
where
	C::Target: chain::Access,
	L::Target: Logger,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		core::mem::swap(&mut ret, &mut pending_events);
		ret
	}
}

#[derive(Clone, Debug, PartialEq)]
/// Details about one direction of a channel as received within a [`ChannelUpdate`].
pub struct ChannelUpdateInfo {
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

impl fmt::Display for ChannelUpdateInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "last_update {}, enabled {}, cltv_expiry_delta {}, htlc_minimum_msat {}, fees {:?}", self.last_update, self.enabled, self.cltv_expiry_delta, self.htlc_minimum_msat, self.fees)?;
		Ok(())
	}
}

impl_writeable_tlv_based!(ChannelUpdateInfo, {
	(0, last_update, required),
	(2, enabled, required),
	(4, cltv_expiry_delta, required),
	(6, htlc_minimum_msat, required),
	(8, htlc_maximum_msat, required),
	(10, fees, required),
	(12, last_update_message, required),
});

#[derive(Clone, Debug, PartialEq)]
/// Details about a channel (both directions).
/// Received within a channel announcement.
pub struct ChannelInfo {
	/// Protocol features of a channel communicated during its announcement
	pub features: ChannelFeatures,
	/// Source node of the first direction of a channel
	pub node_one: NodeId,
	/// Details about the first direction of a channel
	pub one_to_two: Option<ChannelUpdateInfo>,
	/// Source node of the second direction of a channel
	pub node_two: NodeId,
	/// Details about the second direction of a channel
	pub two_to_one: Option<ChannelUpdateInfo>,
	/// The channel capacity as seen on-chain, if chain lookup is available.
	pub capacity_sats: Option<u64>,
	/// An initial announcement of the channel
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub announcement_message: Option<ChannelAnnouncement>,
	/// The timestamp when we received the announcement, if we are running with feature = "std"
	/// (which we can probably assume we are - no-std environments probably won't have a full
	/// network graph in memory!).
	announcement_received_time: u64,
}

impl ChannelInfo {
	/// Returns a [`DirectedChannelInfo`] for the channel directed to the given `target` from a
	/// returned `source`, or `None` if `target` is not one of the channel's counterparties.
	pub fn as_directed_to(&self, target: &NodeId) -> Option<(DirectedChannelInfo, &NodeId)> {
		let (direction, source) = {
			if target == &self.node_one {
				(self.two_to_one.as_ref(), &self.node_two)
			} else if target == &self.node_two {
				(self.one_to_two.as_ref(), &self.node_one)
			} else {
				return None;
			}
		};
		Some((DirectedChannelInfo { channel: self, direction }, source))
	}

	/// Returns a [`DirectedChannelInfo`] for the channel directed from the given `source` to a
	/// returned `target`, or `None` if `source` is not one of the channel's counterparties.
	pub fn as_directed_from(&self, source: &NodeId) -> Option<(DirectedChannelInfo, &NodeId)> {
		let (direction, target) = {
			if source == &self.node_one {
				(self.one_to_two.as_ref(), &self.node_two)
			} else if source == &self.node_two {
				(self.two_to_one.as_ref(), &self.node_one)
			} else {
				return None;
			}
		};
		Some((DirectedChannelInfo { channel: self, direction }, target))
	}
}

impl fmt::Display for ChannelInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "features: {}, node_one: {}, one_to_two: {:?}, node_two: {}, two_to_one: {:?}",
		   log_bytes!(self.features.encode()), log_bytes!(self.node_one.as_slice()), self.one_to_two, log_bytes!(self.node_two.as_slice()), self.two_to_one)?;
		Ok(())
	}
}

impl_writeable_tlv_based!(ChannelInfo, {
	(0, features, required),
	(1, announcement_received_time, (default_value, 0)),
	(2, node_one, required),
	(4, one_to_two, required),
	(6, node_two, required),
	(8, two_to_one, required),
	(10, capacity_sats, required),
	(12, announcement_message, required),
});

/// A wrapper around [`ChannelInfo`] representing information about the channel as directed from a
/// source node to a target node.
#[derive(Clone)]
pub struct DirectedChannelInfo<'a> {
	channel: &'a ChannelInfo,
	direction: Option<&'a ChannelUpdateInfo>,
}

impl<'a> DirectedChannelInfo<'a> {
	/// Returns information for the channel.
	pub fn channel(&self) -> &'a ChannelInfo { self.channel }

	/// Returns information for the direction.
	pub fn direction(&self) -> Option<&'a ChannelUpdateInfo> { self.direction }

	/// Returns the [`EffectiveCapacity`] of the channel in the direction.
	///
	/// This is either the total capacity from the funding transaction, if known, or the
	/// `htlc_maximum_msat` for the direction as advertised by the gossip network, if known,
	/// whichever is smaller.
	pub fn effective_capacity(&self) -> EffectiveCapacity {
		let capacity_msat = self.channel.capacity_sats.map(|capacity_sats| capacity_sats * 1000);
		self.direction
			.and_then(|direction| direction.htlc_maximum_msat)
			.map(|max_htlc_msat| {
				let capacity_msat = capacity_msat.unwrap_or(u64::max_value());
				if max_htlc_msat < capacity_msat {
					EffectiveCapacity::MaximumHTLC { amount_msat: max_htlc_msat }
				} else {
					EffectiveCapacity::Total { capacity_msat }
				}
			})
			.or_else(|| capacity_msat.map(|capacity_msat|
					EffectiveCapacity::Total { capacity_msat }))
			.unwrap_or(EffectiveCapacity::Unknown { previously_used_msat: 0 })
	}

	/// Returns `Some` if [`ChannelUpdateInfo`] is available in the direction.
	pub(super) fn with_update(self) -> Option<DirectedChannelInfoWithUpdate<'a>> {
		match self.direction {
			Some(_) => Some(DirectedChannelInfoWithUpdate { inner: self }),
			None => None,
		}
	}
}

impl<'a> fmt::Debug for DirectedChannelInfo<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		f.debug_struct("DirectedChannelInfo")
			.field("channel", &self.channel)
			.finish()
	}
}

/// A [`DirectedChannelInfo`] with [`ChannelUpdateInfo`] available in its direction.
#[derive(Clone)]
pub(super) struct DirectedChannelInfoWithUpdate<'a> {
	inner: DirectedChannelInfo<'a>,
}

impl<'a> DirectedChannelInfoWithUpdate<'a> {
	/// Returns information for the channel.
	#[inline]
	pub(super) fn channel(&self) -> &'a ChannelInfo { &self.inner.channel }

	/// Returns information for the direction.
	#[inline]
	pub(super) fn direction(&self) -> &'a ChannelUpdateInfo { self.inner.direction.unwrap() }

	/// Returns the [`EffectiveCapacity`] of the channel in the direction.
	#[inline]
	pub(super) fn effective_capacity(&self) -> EffectiveCapacity { self.inner.effective_capacity() }
}

impl<'a> fmt::Debug for DirectedChannelInfoWithUpdate<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.inner.fmt(f)
	}
}

/// The effective capacity of a channel for routing purposes.
///
/// While this may be smaller than the actual channel capacity, amounts greater than
/// [`Self::as_msat_with_default`] should not be routed through the channel.
#[derive(Copy, Clone, PartialEq)]
pub enum EffectiveCapacity {
	/// The available liquidity in the channel known from being a channel counterparty, and thus a
	/// direct hop.
	ExactLiquidity {
		/// Either the inbound or outbound liquidity depending on the direction, denominated in
		/// millisatoshi.
		liquidity_msat: u64,
	},
	/// The maximum HTLC amount in one direction as advertised on the gossip network.
	MaximumHTLC {
		/// The maximum HTLC amount denominated in millisatoshi.
		amount_msat: u64,
	},
	/// The total capacity of the channel as determined by the funding transaction.
	Total {
		/// The funding amount denominated in millisatoshi.
		capacity_msat: u64,
	},
	/// A capacity sufficient to route any payment, typically used for private channels provided by
	/// an invoice.
	Infinite,
	/// A capacity that is unknown possibly because either the chain state is unavailable to know
	/// the total capacity or the `htlc_maximum_msat` was not advertised on the gossip network.
	Unknown {
		/// An amount which should be considered "already used". Used during routing to keep track
		/// of how much we're already considering routing through this channel.
		previously_used_msat: u64,
	},
}

/// The presumed channel capacity denominated in millisatoshi for [`EffectiveCapacity::Unknown`] to
/// use when making routing decisions.
pub const UNKNOWN_CHANNEL_CAPACITY_MSAT: u64 = 250_000 * 1000;

impl EffectiveCapacity {
	#[inline]
	pub(crate) fn as_msat_without_bounds(&self) -> u64 {
		match self {
			EffectiveCapacity::ExactLiquidity { liquidity_msat } => *liquidity_msat,
			EffectiveCapacity::MaximumHTLC { amount_msat } => *amount_msat,
			EffectiveCapacity::Total { capacity_msat } => *capacity_msat,
			EffectiveCapacity::Infinite => u64::max_value(),
			EffectiveCapacity::Unknown { previously_used_msat } => UNKNOWN_CHANNEL_CAPACITY_MSAT.saturating_sub(*previously_used_msat),
		}
	}

	/// Returns the effective capacity denominated in millisatoshi.
	///
	/// Returns [`UNKNOWN_CHANNEL_CAPACITY_MSAT`] minus the `previously_used_msat` for
	/// [`EffectiveCapacity::Unknown`].
	#[inline]
	pub fn as_msat_with_default(&self) -> Option<u64> {
		match self {
			EffectiveCapacity::ExactLiquidity { liquidity_msat } => Some(*liquidity_msat),
			EffectiveCapacity::MaximumHTLC { amount_msat } => Some(*amount_msat),
			EffectiveCapacity::Total { capacity_msat } => Some(*capacity_msat),
			EffectiveCapacity::Infinite => None,
			EffectiveCapacity::Unknown { previously_used_msat } => Some(UNKNOWN_CHANNEL_CAPACITY_MSAT.saturating_sub(*previously_used_msat)),
		}
	}

	/// Returns a new [`EffectiveCapacity`] which is reduced by the given number of millisatoshis
	#[inline]
	pub fn checked_sub(&self, msats: u64) -> Option<EffectiveCapacity> {
		match self {
			Self::ExactLiquidity { liquidity_msat } => match liquidity_msat.checked_sub(msats) {
				Some(liquidity_msat) => Some(Self::ExactLiquidity { liquidity_msat }),
				None => None,
			},
			Self::MaximumHTLC { amount_msat } => match amount_msat.checked_sub(msats) {
				Some(amount_msat) => Some(Self::MaximumHTLC { amount_msat }),
				None => None,
			},
			Self::Total { capacity_msat } => match capacity_msat.checked_sub(msats) {
				Some(capacity_msat) => Some(Self::Total { capacity_msat }),
				None => None,
			},
			Self::Infinite => Some(Self::Infinite),
			Self::Unknown { previously_used_msat } => match previously_used_msat.checked_add(msats) {
				Some(previously_used_msat) => Some(Self::Unknown { previously_used_msat }),
				None => None,
			},
		}
	}
}

/// Fees for routing via a given channel or a node
#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct RoutingFees {
	/// Flat routing fee in satoshis
	pub base_msat: u32,
	/// Liquidity-based routing fee in millionths of a routed amount.
	/// In other words, 10000 is 1%.
	pub proportional_millionths: u32,
}

impl_writeable_tlv_based!(RoutingFees, {
	(0, base_msat, required),
	(2, proportional_millionths, required)
});

#[derive(Clone, Debug, PartialEq)]
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

impl_writeable_tlv_based!(NodeAnnouncementInfo, {
	(0, features, required),
	(2, last_update, required),
	(4, rgb, required),
	(6, alias, required),
	(8, announcement_message, option),
	(10, addresses, vec_type),
});

#[derive(Clone, Debug, PartialEq)]
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

impl_writeable_tlv_based!(NodeInfo, {
	(0, lowest_inbound_channel_fees, option),
	(2, announcement_info, option),
	(4, channels, vec_type),
});

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for NetworkGraph {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.genesis_hash.write(writer)?;
		let channels = self.channels.read().unwrap();
		(channels.len() as u64).write(writer)?;
		for (ref chan_id, ref chan_info) in channels.iter() {
			(*chan_id).write(writer)?;
			chan_info.write(writer)?;
		}
		let nodes = self.nodes.read().unwrap();
		(nodes.len() as u64).write(writer)?;
		for (ref node_id, ref node_info) in nodes.iter() {
			node_id.write(writer)?;
			node_info.write(writer)?;
		}

		write_tlv_fields!(writer, {});
		Ok(())
	}
}

impl Readable for NetworkGraph {
	fn read<R: io::Read>(reader: &mut R) -> Result<NetworkGraph, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

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
		read_tlv_fields!(reader, {});

		Ok(NetworkGraph {
			genesis_hash,
			channels: RwLock::new(channels),
			nodes: RwLock::new(nodes),
		})
	}
}

impl fmt::Display for NetworkGraph {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "Network map\n[Channels]")?;
		for (key, val) in self.channels.read().unwrap().iter() {
			writeln!(f, " {}: {}", key, val)?;
		}
		writeln!(f, "[Nodes]")?;
		for (&node_id, val) in self.nodes.read().unwrap().iter() {
			writeln!(f, " {}: {}", log_bytes!(node_id.as_slice()), val)?;
		}
		Ok(())
	}
}

impl PartialEq for NetworkGraph {
	fn eq(&self, other: &Self) -> bool {
		self.genesis_hash == other.genesis_hash &&
			*self.channels.read().unwrap() == *other.channels.read().unwrap() &&
			*self.nodes.read().unwrap() == *other.nodes.read().unwrap()
	}
}

impl NetworkGraph {
	/// Creates a new, empty, network graph.
	pub fn new(genesis_hash: BlockHash) -> NetworkGraph {
		Self {
			genesis_hash,
			channels: RwLock::new(BTreeMap::new()),
			nodes: RwLock::new(BTreeMap::new()),
		}
	}

	/// Returns a read-only view of the network graph.
	pub fn read_only(&'_ self) -> ReadOnlyNetworkGraph<'_> {
		let channels = self.channels.read().unwrap();
		let nodes = self.nodes.read().unwrap();
		ReadOnlyNetworkGraph {
			channels,
			nodes,
		}
	}

	/// For an already known node (from channel announcements), update its stored properties from a
	/// given node announcement.
	///
	/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	pub fn update_node_from_announcement<T: secp256k1::Verification>(&self, msg: &msgs::NodeAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<(), LightningError> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.signature, &msg.contents.node_id, "node_announcement");
		self.update_node_from_announcement_intern(&msg.contents, Some(&msg))
	}

	/// For an already known node (from channel announcements), update its stored properties from a
	/// given node announcement without verifying the associated signatures. Because we aren't
	/// given the associated signatures here we cannot relay the node announcement to any of our
	/// peers.
	pub fn update_node_from_unsigned_announcement(&self, msg: &msgs::UnsignedNodeAnnouncement) -> Result<(), LightningError> {
		self.update_node_from_announcement_intern(msg, None)
	}

	fn update_node_from_announcement_intern(&self, msg: &msgs::UnsignedNodeAnnouncement, full_msg: Option<&msgs::NodeAnnouncement>) -> Result<(), LightningError> {
		match self.nodes.write().unwrap().get_mut(&NodeId::from_pubkey(&msg.node_id)) {
			None => Err(LightningError{err: "No existing channels for node_announcement".to_owned(), action: ErrorAction::IgnoreError}),
			Some(node) => {
				if let Some(node_info) = node.announcement_info.as_ref() {
					// The timestamp field is somewhat of a misnomer - the BOLTs use it to order
					// updates to ensure you always have the latest one, only vaguely suggesting
					// that it be at least the current time.
					if node_info.last_update  > msg.timestamp {
						return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Gossip)});
					} else if node_info.last_update  == msg.timestamp {
						return Err(LightningError{err: "Update had the same timestamp as last processed update".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
					}
				}

				let should_relay =
					msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY &&
					msg.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY &&
					msg.excess_data.len() + msg.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY;
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
	pub fn update_channel_from_announcement<T: secp256k1::Verification, C: Deref>(
		&self, msg: &msgs::ChannelAnnouncement, chain_access: &Option<C>, secp_ctx: &Secp256k1<T>
	) -> Result<(), LightningError>
	where
		C::Target: chain::Access,
	{
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.node_signature_1, &msg.contents.node_id_1, "channel_announcement");
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.node_signature_2, &msg.contents.node_id_2, "channel_announcement");
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.bitcoin_signature_1, &msg.contents.bitcoin_key_1, "channel_announcement");
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.bitcoin_signature_2, &msg.contents.bitcoin_key_2, "channel_announcement");
		self.update_channel_from_unsigned_announcement_intern(&msg.contents, Some(msg), chain_access)
	}

	/// Store or update channel info from a channel announcement without verifying the associated
	/// signatures. Because we aren't given the associated signatures here we cannot relay the
	/// channel announcement to any of our peers.
	///
	/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
	/// the corresponding UTXO exists on chain and is correctly-formatted.
	pub fn update_channel_from_unsigned_announcement<C: Deref>(
		&self, msg: &msgs::UnsignedChannelAnnouncement, chain_access: &Option<C>
	) -> Result<(), LightningError>
	where
		C::Target: chain::Access,
	{
		self.update_channel_from_unsigned_announcement_intern(msg, None, chain_access)
	}

	fn update_channel_from_unsigned_announcement_intern<C: Deref>(
		&self, msg: &msgs::UnsignedChannelAnnouncement, full_msg: Option<&msgs::ChannelAnnouncement>, chain_access: &Option<C>
	) -> Result<(), LightningError>
	where
		C::Target: chain::Access,
	{
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

		#[allow(unused_mut, unused_assignments)]
		let mut announcement_received_time = 0;
		#[cfg(feature = "std")]
		{
			announcement_received_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
		}

		let chan_info = ChannelInfo {
				features: msg.features.clone(),
				node_one: NodeId::from_pubkey(&msg.node_id_1),
				one_to_two: None,
				node_two: NodeId::from_pubkey(&msg.node_id_2),
				two_to_one: None,
				capacity_sats: utxo_value,
				announcement_message: if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
					{ full_msg.cloned() } else { None },
				announcement_received_time,
			};

		let mut channels = self.channels.write().unwrap();
		let mut nodes = self.nodes.write().unwrap();
		match channels.entry(msg.short_channel_id) {
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
					Self::remove_channel_in_nodes(&mut nodes, &entry.get(), msg.short_channel_id);
					*entry.get_mut() = chan_info;
				} else {
					return Err(LightningError{err: "Already have knowledge of channel".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
				}
			},
			BtreeEntry::Vacant(entry) => {
				entry.insert(chan_info);
			}
		};

		macro_rules! add_channel_to_node {
			( $node_id: expr ) => {
				match nodes.entry($node_id) {
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

		add_channel_to_node!(NodeId::from_pubkey(&msg.node_id_1));
		add_channel_to_node!(NodeId::from_pubkey(&msg.node_id_2));

		Ok(())
	}

	/// Close a channel if a corresponding HTLC fail was sent.
	/// If permanent, removes a channel from the local storage.
	/// May cause the removal of nodes too, if this was their last channel.
	/// If not permanent, makes channels unavailable for routing.
	pub fn close_channel_from_update(&self, short_channel_id: u64, is_permanent: bool) {
		let mut channels = self.channels.write().unwrap();
		if is_permanent {
			if let Some(chan) = channels.remove(&short_channel_id) {
				let mut nodes = self.nodes.write().unwrap();
				Self::remove_channel_in_nodes(&mut nodes, &chan, short_channel_id);
			}
		} else {
			if let Some(chan) = channels.get_mut(&short_channel_id) {
				if let Some(one_to_two) = chan.one_to_two.as_mut() {
					one_to_two.enabled = false;
				}
				if let Some(two_to_one) = chan.two_to_one.as_mut() {
					two_to_one.enabled = false;
				}
			}
		}
	}

	/// Marks a node in the graph as failed.
	pub fn fail_node(&self, _node_id: &PublicKey, is_permanent: bool) {
		if is_permanent {
			// TODO: Wholly remove the node
		} else {
			// TODO: downgrade the node
		}
	}

	#[cfg(feature = "std")]
	/// Removes information about channels that we haven't heard any updates about in some time.
	/// This can be used regularly to prune the network graph of channels that likely no longer
	/// exist.
	///
	/// While there is no formal requirement that nodes regularly re-broadcast their channel
	/// updates every two weeks, the non-normative section of BOLT 7 currently suggests that
	/// pruning occur for updates which are at least two weeks old, which we implement here.
	///
	/// Note that for users of the `lightning-background-processor` crate this method may be
	/// automatically called regularly for you.
	///
	/// This method is only available with the `std` feature. See
	/// [`NetworkGraph::remove_stale_channels_with_time`] for `no-std` use.
	pub fn remove_stale_channels(&self) {
		let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
		self.remove_stale_channels_with_time(time);
	}

	/// Removes information about channels that we haven't heard any updates about in some time.
	/// This can be used regularly to prune the network graph of channels that likely no longer
	/// exist.
	///
	/// While there is no formal requirement that nodes regularly re-broadcast their channel
	/// updates every two weeks, the non-normative section of BOLT 7 currently suggests that
	/// pruning occur for updates which are at least two weeks old, which we implement here.
	///
	/// This function takes the current unix time as an argument. For users with the `std` feature
	/// enabled, [`NetworkGraph::remove_stale_channels`] may be preferable.
	pub fn remove_stale_channels_with_time(&self, current_time_unix: u64) {
		let mut channels = self.channels.write().unwrap();
		// Time out if we haven't received an update in at least 14 days.
		if current_time_unix > u32::max_value() as u64 { return; } // Remove by 2106
		if current_time_unix < STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS { return; }
		let min_time_unix: u32 = (current_time_unix - STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS) as u32;
		// Sadly BTreeMap::retain was only stabilized in 1.53 so we can't switch to it for some
		// time.
		let mut scids_to_remove = Vec::new();
		for (scid, info) in channels.iter_mut() {
			if info.one_to_two.is_some() && info.one_to_two.as_ref().unwrap().last_update < min_time_unix {
				info.one_to_two = None;
			}
			if info.two_to_one.is_some() && info.two_to_one.as_ref().unwrap().last_update < min_time_unix {
				info.two_to_one = None;
			}
			if info.one_to_two.is_none() && info.two_to_one.is_none() {
				// We check the announcement_received_time here to ensure we don't drop
				// announcements that we just received and are just waiting for our peer to send a
				// channel_update for.
				if info.announcement_received_time < min_time_unix as u64 {
					scids_to_remove.push(*scid);
				}
			}
		}
		if !scids_to_remove.is_empty() {
			let mut nodes = self.nodes.write().unwrap();
			for scid in scids_to_remove {
				let info = channels.remove(&scid).expect("We just accessed this scid, it should be present");
				Self::remove_channel_in_nodes(&mut nodes, &info, scid);
			}
		}
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel.
	///
	/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	///
	/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
	/// materially in the future will be rejected.
	pub fn update_channel<T: secp256k1::Verification>(&self, msg: &msgs::ChannelUpdate, secp_ctx: &Secp256k1<T>) -> Result<(), LightningError> {
		self.update_channel_intern(&msg.contents, Some(&msg), Some((&msg.signature, secp_ctx)))
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel without verifying the associated signatures. Because we aren't given the
	/// associated signatures here we cannot relay the channel update to any of our peers.
	///
	/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
	/// materially in the future will be rejected.
	pub fn update_channel_unsigned(&self, msg: &msgs::UnsignedChannelUpdate) -> Result<(), LightningError> {
		self.update_channel_intern(msg, None, None::<(&secp256k1::Signature, &Secp256k1<secp256k1::VerifyOnly>)>)
	}

	fn update_channel_intern<T: secp256k1::Verification>(&self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>, sig_info: Option<(&secp256k1::Signature, &Secp256k1<T>)>) -> Result<(), LightningError> {
		let dest_node_id;
		let chan_enabled = msg.flags & (1 << 1) != (1 << 1);
		let chan_was_enabled;

		#[cfg(all(feature = "std", not(test), not(feature = "_test_utils")))]
		{
			// Note that many tests rely on being able to set arbitrarily old timestamps, thus we
			// disable this check during tests!
			let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			if (msg.timestamp as u64) < time - STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS {
				return Err(LightningError{err: "channel_update is older than two weeks old".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Gossip)});
			}
			if msg.timestamp as u64 > time + 60 * 60 * 24 {
				return Err(LightningError{err: "channel_update has a timestamp more than a day in the future".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Gossip)});
			}
		}

		let mut channels = self.channels.write().unwrap();
		match channels.get_mut(&msg.short_channel_id) {
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
							// The timestamp field is somewhat of a misnomer - the BOLTs use it to
							// order updates to ensure you always have the latest one, only
							// suggesting  that it be at least the current time. For
							// channel_updates specifically, the BOLTs discuss the possibility of
							// pruning based on the timestamp field being more than two weeks old,
							// but only in the non-normative section.
							if existing_chan_info.last_update > msg.timestamp {
								return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Gossip)});
							} else if existing_chan_info.last_update == msg.timestamp {
								return Err(LightningError{err: "Update had same timestamp as last processed update".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
							}
							chan_was_enabled = existing_chan_info.enabled;
						} else {
							chan_was_enabled = false;
						}

						let last_update_message = if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
							{ full_msg.cloned() } else { None };

						let updated_channel_update_info = ChannelUpdateInfo {
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
						$target = Some(updated_channel_update_info);
					}
				}

				let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
				if msg.flags & 1 == 1 {
					dest_node_id = channel.node_one.clone();
					if let Some((sig, ctx)) = sig_info {
						secp_verify_sig!(ctx, &msg_hash, &sig, &PublicKey::from_slice(channel.node_two.as_slice()).map_err(|_| LightningError{
							err: "Couldn't parse source node pubkey".to_owned(),
							action: ErrorAction::IgnoreAndLog(Level::Debug)
						})?, "channel_update");
					}
					maybe_update_channel_info!(channel.two_to_one, channel.node_two);
				} else {
					dest_node_id = channel.node_two.clone();
					if let Some((sig, ctx)) = sig_info {
						secp_verify_sig!(ctx, &msg_hash, &sig, &PublicKey::from_slice(channel.node_one.as_slice()).map_err(|_| LightningError{
							err: "Couldn't parse destination node pubkey".to_owned(),
							action: ErrorAction::IgnoreAndLog(Level::Debug)
						})?, "channel_update");
					}
					maybe_update_channel_info!(channel.one_to_two, channel.node_one);
				}
			}
		}

		let mut nodes = self.nodes.write().unwrap();
		if chan_enabled {
			let node = nodes.get_mut(&dest_node_id).unwrap();
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
			let node = nodes.get_mut(&dest_node_id).unwrap();
			let mut lowest_inbound_channel_fees = None;

			for chan_id in node.channels.iter() {
				let chan = channels.get(chan_id).unwrap();
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

	fn remove_channel_in_nodes(nodes: &mut BTreeMap<NodeId, NodeInfo>, chan: &ChannelInfo, short_channel_id: u64) {
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

impl ReadOnlyNetworkGraph<'_> {
	/// Returns all known valid channels' short ids along with announced channel info.
	///
	/// (C-not exported) because we have no mapping for `BTreeMap`s
	pub fn channels(&self) -> &BTreeMap<u64, ChannelInfo> {
		&*self.channels
	}

	/// Returns all known nodes' public keys along with announced node info.
	///
	/// (C-not exported) because we have no mapping for `BTreeMap`s
	pub fn nodes(&self) -> &BTreeMap<NodeId, NodeInfo> {
		&*self.nodes
	}

	/// Get network addresses by node id.
	/// Returns None if the requested node is completely unknown,
	/// or if node announcement for the node was never received.
	pub fn get_addresses(&self, pubkey: &PublicKey) -> Option<Vec<NetAddress>> {
		if let Some(node) = self.nodes.get(&NodeId::from_pubkey(&pubkey)) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				return Some(node_info.addresses.clone())
			}
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use chain;
	use ln::PaymentHash;
	use ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
	use routing::network_graph::{NetGraphMsgHandler, NetworkGraph, NetworkUpdate, MAX_EXCESS_BYTES_FOR_RELAY};
	use ln::msgs::{Init, OptionalField, RoutingMessageHandler, UnsignedNodeAnnouncement, NodeAnnouncement,
		UnsignedChannelAnnouncement, ChannelAnnouncement, UnsignedChannelUpdate, ChannelUpdate, 
		ReplyChannelRange, ReplyShortChannelIdsEnd, QueryChannelRange, QueryShortChannelIds, MAX_VALUE_MSAT};
	use util::test_utils;
	use util::logger::Logger;
	use util::ser::{Readable, Writeable};
	use util::events::{Event, EventHandler, MessageSendEvent, MessageSendEventsProvider};
	use util::scid_utils::scid_from_parts;

	use super::STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS;

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::{Builder, Script};
	use bitcoin::blockdata::transaction::TxOut;
	use bitcoin::blockdata::opcodes;

	use hex;

	use bitcoin::secp256k1::key::{PublicKey, SecretKey};
	use bitcoin::secp256k1::{All, Secp256k1};

	use io;
	use prelude::*;
	use sync::Arc;

	fn create_network_graph() -> NetworkGraph {
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		NetworkGraph::new(genesis_hash)
	}

	fn create_net_graph_msg_handler(network_graph: &NetworkGraph) -> (
		Secp256k1<All>, NetGraphMsgHandler<&NetworkGraph, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let net_graph_msg_handler = NetGraphMsgHandler::new(network_graph, None, Arc::clone(&logger));
		(secp_ctx, net_graph_msg_handler)
	}

	#[test]
	fn request_full_sync_finite_times() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()[..]).unwrap());

		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(net_graph_msg_handler.should_request_full_sync(&node_id));
		assert!(!net_graph_msg_handler.should_request_full_sync(&node_id));
	}

	fn get_signed_node_announcement<F: Fn(&mut UnsignedNodeAnnouncement)>(f: F, node_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> NodeAnnouncement {
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_key);
		let mut unsigned_announcement = UnsignedNodeAnnouncement {
			features: NodeFeatures::known(),
			timestamp: 100,
			node_id: node_id,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		f(&mut unsigned_announcement);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_key),
			contents: unsigned_announcement
		}
	}

	fn get_signed_channel_announcement<F: Fn(&mut UnsignedChannelAnnouncement)>(f: F, node_1_key: &SecretKey, node_2_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> ChannelAnnouncement {
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_key);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_key);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

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
		f(&mut unsigned_announcement);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_key),
			node_signature_2: secp_ctx.sign(&msghash, node_2_key),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_btckey),
			contents: unsigned_announcement,
		}
	}

	fn get_channel_script(secp_ctx: &Secp256k1<secp256k1::All>) -> Script {
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();
		Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
		              .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_1_btckey).serialize())
		              .push_slice(&PublicKey::from_secret_key(&secp_ctx, node_2_btckey).serialize())
		              .push_opcode(opcodes::all::OP_PUSHNUM_2)
		              .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
		              .to_v0_p2wsh()
	}

	fn get_signed_channel_update<F: Fn(&mut UnsignedChannelUpdate)>(f: F, node_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> ChannelUpdate {
		let mut unsigned_channel_update = UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 0,
			timestamp: 100,
			flags: 0,
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1_000_000,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 10_000,
			fee_proportional_millionths: 20,
			excess_data: Vec::new()
		};
		f(&mut unsigned_channel_update);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_key),
			contents: unsigned_channel_update
		}
	}

	#[test]
	fn handling_node_announcements() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let zero_hash = Sha256dHash::hash(&[0; 32]);

		let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!("No existing channels for node_announcement", e.err)
		};

		{
			// Announce a channel to add a corresponding node.
			let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
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
				contents: valid_announcement.contents.clone()
		}) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature on node_announcement message")
		};

		let announcement_with_data = get_signed_node_announcement(|unsigned_announcement| {
			unsigned_announcement.timestamp += 1000;
			unsigned_announcement.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
		}, node_1_privkey, &secp_ctx);
		// Return false because contains excess data.
		match net_graph_msg_handler.handle_node_announcement(&announcement_with_data) {
			Ok(res) => assert!(!res),
			Err(_) => panic!()
		};

		// Even though previous announcement was not relayed further, we still accepted it,
		// so we now won't accept announcements before the previous one.
		let outdated_announcement = get_signed_node_announcement(|unsigned_announcement| {
			unsigned_announcement.timestamp += 1000 - 10;
		}, node_1_privkey, &secp_ctx);
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

		let good_script = get_channel_script(&secp_ctx);
		let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);

		// Test if the UTXO lookups were not supported
		let network_graph = NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash());
		let mut net_graph_msg_handler = NetGraphMsgHandler::new(&network_graph, None, Arc::clone(&logger));
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			match network_graph.read_only().channels().get(&valid_announcement.contents.short_channel_id) {
				None => panic!(),
				Some(_) => ()
			};
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
		let network_graph = NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash());
		net_graph_msg_handler = NetGraphMsgHandler::new(&network_graph, Some(chain_source.clone()), Arc::clone(&logger));

		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 1;
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announced without corresponding UTXO entry")
		};

		// Now test if the transaction is found in the UTXO set and the script is correct.
		*chain_source.utxo_ret.lock().unwrap() = Ok(TxOut { value: 0, script_pubkey: good_script.clone() });
		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 2;
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			match network_graph.read_only().channels().get(&valid_announcement.contents.short_channel_id) {
				None => panic!(),
				Some(_) => ()
			};
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
		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.features = ChannelFeatures::empty();
			unsigned_announcement.short_channel_id += 2;
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};
		{
			match network_graph.read_only().channels().get(&valid_announcement.contents.short_channel_id) {
				Some(channel_entry) => {
					assert_eq!(channel_entry.features, ChannelFeatures::empty());
				},
				_ => panic!()
			};
		}

		// Don't relay valid channels with excess data
		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 3;
			unsigned_announcement.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};

		let mut invalid_sig_announcement = valid_announcement.clone();
		invalid_sig_announcement.contents.excess_data = Vec::new();
		match net_graph_msg_handler.handle_channel_announcement(&invalid_sig_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature on channel_announcement message")
		};

		let channel_to_itself_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_1_privkey, &secp_ctx);
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
		let network_graph = NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash());
		let net_graph_msg_handler = NetGraphMsgHandler::new(&network_graph, Some(chain_source.clone()), Arc::clone(&logger));

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let amount_sats = 1000_000;
		let short_channel_id;

		{
			// Announce a channel we will update
			let good_script = get_channel_script(&secp_ctx);
			*chain_source.utxo_ret.lock().unwrap() = Ok(TxOut { value: amount_sats, script_pubkey: good_script.clone() });

			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			short_channel_id = valid_channel_announcement.contents.short_channel_id;
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

		}

		let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			match network_graph.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert_eq!(channel_info.one_to_two.as_ref().unwrap().cltv_expiry_delta, 144);
					assert!(channel_info.two_to_one.is_none());
				}
			};
		}

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 100;
			unsigned_channel_update.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
		}, node_1_privkey, &secp_ctx);
		// Return false because contains excess data
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 110;
			unsigned_channel_update.short_channel_id += 1;
		}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Couldn't find channel for update")
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.htlc_maximum_msat = OptionalField::Present(MAX_VALUE_MSAT + 1);
			unsigned_channel_update.timestamp += 110;
		}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than maximum possible msats")
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.htlc_maximum_msat = OptionalField::Present(amount_sats * 1000 + 1);
			unsigned_channel_update.timestamp += 110;
		}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than channel capacity or capacity is bogus")
		};

		// Even though previous update was not relayed further, we still accepted it,
		// so we now won't accept update before the previous one.
		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 100;
		}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Update had same timestamp as last processed update")
		};

		let mut invalid_sig_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 500;
		}, node_1_privkey, &secp_ctx);
		let zero_hash = Sha256dHash::hash(&[0; 32]);
		let fake_msghash = hash_to_message!(&zero_hash);
		invalid_sig_channel_update.signature = secp_ctx.sign(&fake_msghash, node_1_privkey);
		match net_graph_msg_handler.handle_channel_update(&invalid_sig_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature on channel_update message")
		};
	}

	#[test]
	fn handling_network_update() {
		let logger = test_utils::TestLogger::new();
		let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let network_graph = NetworkGraph::new(genesis_hash);
		let net_graph_msg_handler = NetGraphMsgHandler::new(&network_graph, Some(chain_source.clone()), &logger);
		let secp_ctx = Secp256k1::new();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		{
			// There is no nodes in the table at the beginning.
			assert_eq!(network_graph.read_only().nodes().len(), 0);
		}

		let short_channel_id;
		{
			// Announce a channel we will update
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			short_channel_id = valid_channel_announcement.contents.short_channel_id;
			let chain_source: Option<&test_utils::TestChainSource> = None;
			assert!(network_graph.update_channel_from_announcement(&valid_channel_announcement, &chain_source, &secp_ctx).is_ok());
			assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());

			let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_none());

			net_graph_msg_handler.handle_event(&Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([0; 32]),
				rejected_by_dest: false,
				all_paths_failed: true,
				path: vec![],
				network_update: Some(NetworkUpdate::ChannelUpdateMessage {
					msg: valid_channel_update,
				}),
				short_channel_id: None,
				retry: None,
				error_code: None,
				error_data: None,
			});

			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_some());
		}

		// Non-permanent closing just disables a channel
		{
			match network_graph.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(channel_info.one_to_two.as_ref().unwrap().enabled);
				}
			};

			net_graph_msg_handler.handle_event(&Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([0; 32]),
				rejected_by_dest: false,
				all_paths_failed: true,
				path: vec![],
				network_update: Some(NetworkUpdate::ChannelClosed {
					short_channel_id,
					is_permanent: false,
				}),
				short_channel_id: None,
				retry: None,
				error_code: None,
				error_data: None,
			});

			match network_graph.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(!channel_info.one_to_two.as_ref().unwrap().enabled);
				}
			};
		}

		// Permanent closing deletes a channel
		net_graph_msg_handler.handle_event(&Event::PaymentPathFailed {
			payment_id: None,
			payment_hash: PaymentHash([0; 32]),
			rejected_by_dest: false,
			all_paths_failed: true,
			path: vec![],
			network_update: Some(NetworkUpdate::ChannelClosed {
				short_channel_id,
				is_permanent: true,
			}),
			short_channel_id: None,
			retry: None,
			error_code: None,
			error_data: None,
		});

		assert_eq!(network_graph.read_only().channels().len(), 0);
		// Nodes are also deleted because there are no associated channels anymore
		assert_eq!(network_graph.read_only().nodes().len(), 0);
		// TODO: Test NetworkUpdate::NodeFailure, which is not implemented yet.
	}

	#[test]
	fn test_channel_timeouts() {
		// Test the removal of channels with `remove_stale_channels`.
		let logger = test_utils::TestLogger::new();
		let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let network_graph = NetworkGraph::new(genesis_hash);
		let net_graph_msg_handler = NetGraphMsgHandler::new(&network_graph, Some(chain_source.clone()), &logger);
		let secp_ctx = Secp256k1::new();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		let short_channel_id = valid_channel_announcement.contents.short_channel_id;
		let chain_source: Option<&test_utils::TestChainSource> = None;
		assert!(network_graph.update_channel_from_announcement(&valid_channel_announcement, &chain_source, &secp_ctx).is_ok());
		assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());

		let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
		assert!(net_graph_msg_handler.handle_channel_update(&valid_channel_update).is_ok());
		assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_some());

		network_graph.remove_stale_channels_with_time(100 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
		assert_eq!(network_graph.read_only().channels().len(), 1);
		assert_eq!(network_graph.read_only().nodes().len(), 2);

		network_graph.remove_stale_channels_with_time(101 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
		#[cfg(feature = "std")]
		{
			// In std mode, a further check is performed before fully removing the channel -
			// the channel_announcement must have been received at least two weeks ago. We
			// fudge that here by indicating the time has jumped two weeks. Note that the
			// directional channel information will have been removed already..
			assert_eq!(network_graph.read_only().channels().len(), 1);
			assert_eq!(network_graph.read_only().nodes().len(), 2);
			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_none());

			use std::time::{SystemTime, UNIX_EPOCH};
			let announcement_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			network_graph.remove_stale_channels_with_time(announcement_time + 1 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
		}

		assert_eq!(network_graph.read_only().channels().len(), 0);
		assert_eq!(network_graph.read_only().nodes().len(), 0);
	}

	#[test]
	fn getting_next_channel_announcements() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		// Channels were not announced yet.
		let channels_with_announcements = net_graph_msg_handler.get_next_channel_announcements(0, 1);
		assert_eq!(channels_with_announcements.len(), 0);

		let short_channel_id;
		{
			// Announce a channel we will update
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			short_channel_id = valid_channel_announcement.contents.short_channel_id;
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
			let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
				unsigned_channel_update.timestamp = 101;
			}, node_1_privkey, &secp_ctx);
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
			let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
				unsigned_channel_update.timestamp = 102;
				unsigned_channel_update.excess_data = [1; MAX_EXCESS_BYTES_FOR_RELAY + 1].to_vec();
			}, node_1_privkey, &secp_ctx);
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
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);

		// No nodes yet.
		let next_announcements = net_graph_msg_handler.get_next_node_announcements(None, 10);
		assert_eq!(next_announcements.len(), 0);

		{
			// Announce a channel to add 2 nodes
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			match net_graph_msg_handler.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}


		// Nodes were never announced
		let next_announcements = net_graph_msg_handler.get_next_node_announcements(None, 3);
		assert_eq!(next_announcements.len(), 0);

		{
			let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
			match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

			let valid_announcement = get_signed_node_announcement(|_| {}, node_2_privkey, &secp_ctx);
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
			let valid_announcement = get_signed_node_announcement(|unsigned_announcement| {
				unsigned_announcement.timestamp += 10;
				unsigned_announcement.excess_data = [1; MAX_EXCESS_BYTES_FOR_RELAY + 1].to_vec();
			}, node_2_privkey, &secp_ctx);
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
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		// Announce a channel to add a corresponding node.
		let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};

		let mut w = test_utils::TestVecWriter(Vec::new());
		assert!(!network_graph.read_only().nodes().is_empty());
		assert!(!network_graph.read_only().channels().is_empty());
		network_graph.write(&mut w).unwrap();
		assert!(<NetworkGraph>::read(&mut io::Cursor::new(&w.0)).unwrap() == network_graph);
	}

	#[test]
	fn calling_sync_routing_table() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let first_blocknum = 0;
		let number_of_blocks = 0xffff_ffff;

		// It should ignore if gossip_queries feature is not enabled
		{
			let init_msg = Init { features: InitFeatures::known().clear_gossip_queries(), remote_network_address: None };
			net_graph_msg_handler.peer_connected(&node_id_1, &init_msg);
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 0);
		}

		// It should send a query_channel_message with the correct information
		{
			let init_msg = Init { features: InitFeatures::known(), remote_network_address: None };
			net_graph_msg_handler.peer_connected(&node_id_1, &init_msg);
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 2);
			match &events[0] {
				MessageSendEvent::SendGossipTimestampFilter{ node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.first_timestamp, 0);
					assert_eq!(msg.timestamp_range, u32::max_value());
				},
				_ => panic!("Expected MessageSendEvent::SendChannelRangeQuery")
			};
			match &events[1] {
				MessageSendEvent::SendChannelRangeQuery{ node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.first_blocknum, first_blocknum);
					assert_eq!(msg.number_of_blocks, number_of_blocks);
				},
				_ => panic!("Expected MessageSendEvent::SendChannelRangeQuery")
			};
		}

		// It should not enqueue a query when should_request_full_sync return false.
		// The initial implementation allows syncing with the first 5 peers after
		// which should_request_full_sync will return false
		{
			let network_graph = create_network_graph();
			let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
			let init_msg = Init { features: InitFeatures::known(), remote_network_address: None };
			for n in 1..7 {
				let node_privkey = &SecretKey::from_slice(&[n; 32]).unwrap();
				let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);
				net_graph_msg_handler.peer_connected(&node_id, &init_msg);
				let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
				if n <= 5 {
					assert_eq!(events.len(), 2);
				} else {
					// Even after the we stop sending the explicit query, we should still send a
					// gossip_timestamp_filter on each new connection.
					assert_eq!(events.len(), 1);
				}

			}
		}
	}

	#[test]
	fn handling_reply_channel_range() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// Test receipt of a single reply that should enqueue an SCID query
		// matching the SCIDs in the reply
		{
			let result = net_graph_msg_handler.handle_reply_channel_range(&node_id_1, ReplyChannelRange {
				chain_hash,
				sync_complete: true,
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

			// We expect to emit a query_short_channel_ids message with the received scids
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendShortIdsQuery { node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					assert_eq!(msg.short_channel_ids, vec![
						0x0003e0_000000_0000, // 992x0x0
						0x0003e8_000000_0000, // 1000x0x0
						0x0003e9_000000_0000, // 1001x0x0
						0x0003f0_000000_0000, // 1008x0x0
						0x00044c_000000_0000, // 1100x0x0
						0x0006e0_000000_0000, // 1760x0x0
					]);
				},
				_ => panic!("expected MessageSendEvent::SendShortIdsQuery"),
			}
		}
	}

	#[test]
	fn handling_reply_short_channel_ids() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// Test receipt of a successful reply
		{
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: true,
			});
			assert!(result.is_ok());
		}

		// Test receipt of a reply that indicates the peer does not maintain up-to-date information
		// for the chain_hash requested in the query.
		{
			let result = net_graph_msg_handler.handle_reply_short_channel_ids_end(&node_id, ReplyShortChannelIdsEnd {
				chain_hash,
				full_information: false,
			});
			assert!(result.is_err());
			assert_eq!(result.err().unwrap().err, "Received reply_short_channel_ids_end with no information");
		}
	}

	#[test]
	fn handling_query_channel_range() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);

		let mut scids: Vec<u64> = vec![
			scid_from_parts(0xfffffe, 0xffffff, 0xffff).unwrap(), // max
			scid_from_parts(0xffffff, 0xffffff, 0xffff).unwrap(), // never
		];

		// used for testing multipart reply across blocks
		for block in 100000..=108001 {
			scids.push(scid_from_parts(block, 0, 0).unwrap());
		}

		// used for testing resumption on same block
		scids.push(scid_from_parts(108001, 1, 0).unwrap());

		for scid in scids {
			let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
				unsigned_announcement.short_channel_id = scid;
			}, node_1_privkey, node_2_privkey, &secp_ctx);
			match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
				Ok(_) => (),
				_ => panic!()
			};
		}

		// Error when number_of_blocks=0
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0,
				number_of_blocks: 0,
			},
			false,
			vec![ReplyChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0,
				number_of_blocks: 0,
				sync_complete: true,
				short_channel_ids: vec![]
			}]
		);

		// Error when wrong chain
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: genesis_block(Network::Bitcoin).header.block_hash(),
				first_blocknum: 0,
				number_of_blocks: 0xffff_ffff,
			},
			false,
			vec![ReplyChannelRange {
				chain_hash: genesis_block(Network::Bitcoin).header.block_hash(),
				first_blocknum: 0,
				number_of_blocks: 0xffff_ffff,
				sync_complete: true,
				short_channel_ids: vec![],
			}]
		);

		// Error when first_blocknum > 0xffffff
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0x01000000,
				number_of_blocks: 0xffff_ffff,
			},
			false,
			vec![ReplyChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0x01000000,
				number_of_blocks: 0xffff_ffff,
				sync_complete: true,
				short_channel_ids: vec![]
			}]
		);

		// Empty reply when max valid SCID block num
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0xffffff,
				number_of_blocks: 1,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 0xffffff,
					number_of_blocks: 1,
					sync_complete: true,
					short_channel_ids: vec![]
				},
			]
		);

		// No results in valid query range
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 1000,
				number_of_blocks: 1000,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 1000,
					number_of_blocks: 1000,
					sync_complete: true,
					short_channel_ids: vec![],
				}
			]
		);

		// Overflow first_blocknum + number_of_blocks
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 0xfe0000,
				number_of_blocks: 0xffffffff,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 0xfe0000,
					number_of_blocks: 0xffffffff - 0xfe0000,
					sync_complete: true,
					short_channel_ids: vec![
						0xfffffe_ffffff_ffff, // max
					]
				}
			]
		);

		// Single block exactly full
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 100000,
				number_of_blocks: 8000,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 100000,
					number_of_blocks: 8000,
					sync_complete: true,
					short_channel_ids: (100000..=107999)
						.map(|block| scid_from_parts(block, 0, 0).unwrap())
						.collect(),
				},
			]
		);

		// Multiple split on new block
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 100000,
				number_of_blocks: 8001,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 100000,
					number_of_blocks: 7999,
					sync_complete: false,
					short_channel_ids: (100000..=107999)
						.map(|block| scid_from_parts(block, 0, 0).unwrap())
						.collect(),
				},
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 107999,
					number_of_blocks: 2,
					sync_complete: true,
					short_channel_ids: vec![
						scid_from_parts(108000, 0, 0).unwrap(),
					],
				}
			]
		);

		// Multiple split on same block
		do_handling_query_channel_range(
			&net_graph_msg_handler,
			&node_id_2,
			QueryChannelRange {
				chain_hash: chain_hash.clone(),
				first_blocknum: 100002,
				number_of_blocks: 8000,
			},
			true,
			vec![
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 100002,
					number_of_blocks: 7999,
					sync_complete: false,
					short_channel_ids: (100002..=108001)
						.map(|block| scid_from_parts(block, 0, 0).unwrap())
						.collect(),
				},
				ReplyChannelRange {
					chain_hash: chain_hash.clone(),
					first_blocknum: 108001,
					number_of_blocks: 1,
					sync_complete: true,
					short_channel_ids: vec![
						scid_from_parts(108001, 1, 0).unwrap(),
					],
				}
			]
		);
	}

	fn do_handling_query_channel_range(
		net_graph_msg_handler: &NetGraphMsgHandler<&NetworkGraph, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		test_node_id: &PublicKey,
		msg: QueryChannelRange,
		expected_ok: bool,
		expected_replies: Vec<ReplyChannelRange>
	) {
		let mut max_firstblocknum = msg.first_blocknum.saturating_sub(1);
		let mut c_lightning_0_9_prev_end_blocknum = max_firstblocknum;
		let query_end_blocknum = msg.end_blocknum();
		let result = net_graph_msg_handler.handle_query_channel_range(test_node_id, msg);

		if expected_ok {
			assert!(result.is_ok());
		} else {
			assert!(result.is_err());
		}

		let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), expected_replies.len());

		for i in 0..events.len() {
			let expected_reply = &expected_replies[i];
			match &events[i] {
				MessageSendEvent::SendReplyChannelRange { node_id, msg } => {
					assert_eq!(node_id, test_node_id);
					assert_eq!(msg.chain_hash, expected_reply.chain_hash);
					assert_eq!(msg.first_blocknum, expected_reply.first_blocknum);
					assert_eq!(msg.number_of_blocks, expected_reply.number_of_blocks);
					assert_eq!(msg.sync_complete, expected_reply.sync_complete);
					assert_eq!(msg.short_channel_ids, expected_reply.short_channel_ids);

					// Enforce exactly the sequencing requirements present on c-lightning v0.9.3
					assert!(msg.first_blocknum == c_lightning_0_9_prev_end_blocknum || msg.first_blocknum == c_lightning_0_9_prev_end_blocknum.saturating_add(1));
					assert!(msg.first_blocknum >= max_firstblocknum);
					max_firstblocknum = msg.first_blocknum;
					c_lightning_0_9_prev_end_blocknum = msg.first_blocknum.saturating_add(msg.number_of_blocks);

					// Check that the last block count is >= the query's end_blocknum
					if i == events.len() - 1 {
						assert!(msg.first_blocknum.saturating_add(msg.number_of_blocks) >= query_end_blocknum);
					}
				},
				_ => panic!("expected MessageSendEvent::SendReplyChannelRange"),
			}
		}
	}

	#[test]
	fn handling_query_short_channel_ids() {
		let network_graph = create_network_graph();
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler(&network_graph);
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		let result = net_graph_msg_handler.handle_query_short_channel_ids(&node_id, QueryShortChannelIds {
			chain_hash,
			short_channel_ids: vec![0x0003e8_000000_0000],
		});
		assert!(result.is_err());
	}
}

#[cfg(all(test, feature = "_bench_unstable"))]
mod benches {
	use super::*;

	use test::Bencher;
	use std::io::Read;

	#[bench]
	fn read_network_graph(bench: &mut Bencher) {
		let mut d = ::routing::router::test_utils::get_route_file().unwrap();
		let mut v = Vec::new();
		d.read_to_end(&mut v).unwrap();
		bench.iter(|| {
			let _ = NetworkGraph::read(&mut std::io::Cursor::new(&v)).unwrap();
		});
	}

	#[bench]
	fn write_network_graph(bench: &mut Bencher) {
		let mut d = ::routing::router::test_utils::get_route_file().unwrap();
		let net_graph = NetworkGraph::read(&mut d).unwrap();
		bench.iter(|| {
			let _ = net_graph.encode();
		});
	}
}
