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
use ln::msgs::{DecodeError, ErrorAction, Init, LightningError, RoutingMessageHandler, NetAddress, MAX_VALUE_MSAT};
use ln::msgs::{ChannelAnnouncement, ChannelUpdate, NodeAnnouncement, OptionalField};
use ln::msgs::{QueryChannelRange, ReplyChannelRange, QueryShortChannelIds, ReplyShortChannelIdsEnd};
use ln::msgs;
use util::ser::{Writeable, Readable, Writer};
use util::logger::{Logger, Level};
use util::events::{MessageSendEvent, MessageSendEventsProvider};
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

/// The maximum number of extra bytes which we do not understand in a gossip message before we will
/// refuse to relay the message.
const MAX_EXCESS_BYTES_FOR_RELAY: usize = 1024;

/// Maximum number of short_channel_ids that will be encoded in one gossip reply message.
/// This value ensures a reply fits within the 65k payload limit and is consistent with other implementations.
const MAX_SCIDS_PER_REPLY: usize = 8000;

/// Represents the network as nodes and channels between them
pub struct NetworkGraph {
	genesis_hash: BlockHash,
	// Lock order: channels -> nodes
	channels: RwLock<BTreeMap<u64, ChannelInfo>>,
	nodes: RwLock<BTreeMap<PublicKey, NodeInfo>>,
}

/// A read-only view of [`NetworkGraph`].
pub struct ReadOnlyNetworkGraph<'a> {
	channels: RwLockReadGuard<'a, BTreeMap<u64, ChannelInfo>>,
	nodes: RwLockReadGuard<'a, BTreeMap<PublicKey, NodeInfo>>,
}

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
pub struct NetGraphMsgHandler<C: Deref, L: Deref> where C::Target: chain::Access, L::Target: Logger {
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	/// Representation of the payment channel network
	pub network_graph: NetworkGraph,
	chain_access: Option<C>,
	full_syncs_requested: AtomicUsize,
	pending_events: Mutex<Vec<MessageSendEvent>>,
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
			network_graph: NetworkGraph::new(genesis_hash),
			full_syncs_requested: AtomicUsize::new(0),
			chain_access,
			pending_events: Mutex::new(vec![]),
			logger,
		}
	}

	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming an existing Network Graph.
	pub fn from_net_graph(chain_access: Option<C>, logger: L, network_graph: NetworkGraph) -> Self {
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
}

macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr ) => {
		match $secp_ctx.verify($msg, $sig, $pubkey) {
			Ok(_) => {},
			Err(_) => return Err(LightningError{err: "Invalid signature from remote node".to_owned(), action: ErrorAction::IgnoreError}),
		}
	};
}

impl<C: Deref , L: Deref > RoutingMessageHandler for NetGraphMsgHandler<C, L> where C::Target: chain::Access, L::Target: Logger {
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_node_from_announcement(msg, &self.secp_ctx)?;
		Ok(msg.contents.excess_data.len() <=  MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_data.len() + msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_channel_from_announcement(msg, &self.chain_access, &self.secp_ctx)?;
		log_trace!(self.logger, "Added channel_announcement for {}{}", msg.contents.short_channel_id, if !msg.contents.excess_data.is_empty() { " with excess uninterpreted data!" } else { "" });
		Ok(msg.contents.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_htlc_fail_channel_update(&self, update: &msgs::HTLCFailChannelUpdate) {
		match update {
			&msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg } => {
				let chan_enabled = msg.contents.flags & (1 << 1) != (1 << 1);
				log_debug!(self.logger, "Updating channel with channel_update from a payment failure. Channel {} is {}abled.", msg.contents.short_channel_id, if chan_enabled { "en" } else { "dis" });
				let _ = self.network_graph.update_channel(msg, &self.secp_ctx);
			},
			&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id, is_permanent } => {
				log_debug!(self.logger, "{} channel graph entry for {} due to a payment failure.", if is_permanent { "Removing" } else { "Disabling" }, short_channel_id);
				self.network_graph.close_channel_from_update(short_channel_id, is_permanent);
			},
			&msgs::HTLCFailChannelUpdate::NodeFailure { ref node_id, is_permanent } => {
				log_debug!(self.logger, "{} node graph entry for {} due to a payment failure.", if is_permanent { "Removing" } else { "Disabling" }, node_id);
				self.network_graph.fail_node(node_id, is_permanent);
			},
		}
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
				let mut iter = nodes.range((*pubkey)..);
				iter.next();
				iter
			} else {
				nodes.range(..)
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
	fn sync_routing_table(&self, their_node_id: &PublicKey, init_msg: &Init) {

		// We will only perform a sync with peers that support gossip_queries.
		if !init_msg.features.supports_gossip_queries() {
			return ();
		}

		// Check if we need to perform a full synchronization with this peer
		if !self.should_request_full_sync(their_node_id) {
			return ();
		}

		let first_blocknum = 0;
		let number_of_blocks = 0xffffffff;
		log_debug!(self.logger, "Sending query_channel_range peer={}, first_blocknum={}, number_of_blocks={}", log_pubkey!(their_node_id), first_blocknum, number_of_blocks);
		let mut pending_events = self.pending_events.lock().unwrap();
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

impl<C: Deref, L: Deref> MessageSendEventsProvider for NetGraphMsgHandler<C, L>
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

impl_writeable_tlv_based!(DirectionalChannelInfo, {
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

impl_writeable_tlv_based!(ChannelInfo, {
	(0, features, required),
	(2, node_one, required),
	(4, one_to_two, required),
	(6, node_two, required),
	(8, two_to_one, required),
	(10, capacity_sats, required),
	(12, announcement_message, required),
});


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
		for (key, val) in self.nodes.read().unwrap().iter() {
			writeln!(f, " {}: {}", log_pubkey!(key), val)?;
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
		secp_verify_sig!(secp_ctx, &msg_hash, &msg.signature, &msg.contents.node_id);
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
		match self.nodes.write().unwrap().get_mut(&msg.node_id) {
			None => Err(LightningError{err: "No existing channels for node_announcement".to_owned(), action: ErrorAction::IgnoreError}),
			Some(node) => {
				if let Some(node_info) = node.announcement_info.as_ref() {
					if node_info.last_update  >= msg.timestamp {
						return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Trace)});
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

		let chan_info = ChannelInfo {
				features: msg.features.clone(),
				node_one: msg.node_id_1.clone(),
				one_to_two: None,
				node_two: msg.node_id_2.clone(),
				two_to_one: None,
				capacity_sats: utxo_value,
				announcement_message: if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
					{ full_msg.cloned() } else { None },
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
					return Err(LightningError{err: "Already have knowledge of channel".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Trace)})
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

		add_channel_to_node!(msg.node_id_1);
		add_channel_to_node!(msg.node_id_2);

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

	fn fail_node(&self, _node_id: &PublicKey, is_permanent: bool) {
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
	pub fn update_channel<T: secp256k1::Verification>(&self, msg: &msgs::ChannelUpdate, secp_ctx: &Secp256k1<T>) -> Result<(), LightningError> {
		self.update_channel_intern(&msg.contents, Some(&msg), Some((&msg.signature, secp_ctx)))
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel without verifying the associated signatures. Because we aren't given the
	/// associated signatures here we cannot relay the channel update to any of our peers.
	pub fn update_channel_unsigned(&self, msg: &msgs::UnsignedChannelUpdate) -> Result<(), LightningError> {
		self.update_channel_intern(msg, None, None::<(&secp256k1::Signature, &Secp256k1<secp256k1::VerifyOnly>)>)
	}

	fn update_channel_intern<T: secp256k1::Verification>(&self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>, sig_info: Option<(&secp256k1::Signature, &Secp256k1<T>)>) -> Result<(), LightningError> {
		let dest_node_id;
		let chan_enabled = msg.flags & (1 << 1) != (1 << 1);
		let chan_was_enabled;

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
							if existing_chan_info.last_update >= msg.timestamp {
								return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreAndLog(Level::Trace)});
							}
							chan_was_enabled = existing_chan_info.enabled;
						} else {
							chan_was_enabled = false;
						}

						let last_update_message = if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
							{ full_msg.cloned() } else { None };

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
	pub fn nodes(&self) -> &BTreeMap<PublicKey, NodeInfo> {
		&*self.nodes
	}

	/// Get network addresses by node id.
	/// Returns None if the requested node is completely unknown,
	/// or if node announcement for the node was never received.
	///
	/// (C-not exported) as there is no practical way to track lifetimes of returned values.
	pub fn get_addresses(&self, pubkey: &PublicKey) -> Option<&Vec<NetAddress>> {
		if let Some(node) = self.nodes.get(pubkey) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				return Some(&node_info.addresses)
			}
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use chain;
	use ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
	use routing::network_graph::{NetGraphMsgHandler, NetworkGraph, MAX_EXCESS_BYTES_FOR_RELAY};
	use ln::msgs::{Init, OptionalField, RoutingMessageHandler, UnsignedNodeAnnouncement, NodeAnnouncement,
		UnsignedChannelAnnouncement, ChannelAnnouncement, UnsignedChannelUpdate, ChannelUpdate, HTLCFailChannelUpdate,
		ReplyChannelRange, ReplyShortChannelIdsEnd, QueryChannelRange, QueryShortChannelIds, MAX_VALUE_MSAT};
	use util::test_utils;
	use util::logger::Logger;
	use util::ser::{Readable, Writeable};
	use util::events::{MessageSendEvent, MessageSendEventsProvider};
	use util::scid_utils::scid_from_parts;

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

	use io;
	use prelude::*;
	use sync::Arc;

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
		unsigned_announcement.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
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
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&unsigned_announcement.short_channel_id) {
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
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&unsigned_announcement.short_channel_id) {
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
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&unsigned_announcement.short_channel_id) {
				Some(channel_entry) => {
					assert_eq!(channel_entry.features, ChannelFeatures::empty());
				},
				_ => panic!()
			};
		}

		// Don't relay valid channels with excess data
		unsigned_announcement.short_channel_id += 1;
		unsigned_announcement.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
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
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert_eq!(channel_info.one_to_two.as_ref().unwrap().cltv_expiry_delta, 144);
					assert!(channel_info.two_to_one.is_none());
				}
			};
		}

		unsigned_channel_update.timestamp += 100;
		unsigned_channel_update.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
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
			let network = &net_graph_msg_handler.network_graph;
			assert_eq!(network.read_only().nodes().len(), 0);
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
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(channel_info.one_to_two.is_some());
				}
			};
		}

		let channel_close_msg = HTLCFailChannelUpdate::ChannelClosed {
			short_channel_id,
			is_permanent: false
		};

		net_graph_msg_handler.handle_htlc_fail_channel_update(&channel_close_msg);

		// Non-permanent closing just disables a channel
		{
			let network = &net_graph_msg_handler.network_graph;
			match network.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(!channel_info.one_to_two.as_ref().unwrap().enabled);
				}
			};
		}

		let channel_close_msg = HTLCFailChannelUpdate::ChannelClosed {
			short_channel_id,
			is_permanent: true
		};

		net_graph_msg_handler.handle_htlc_fail_channel_update(&channel_close_msg);

		// Permanent closing deletes a channel
		{
			let network = &net_graph_msg_handler.network_graph;
			assert_eq!(network.read_only().channels().len(), 0);
			// Nodes are also deleted because there are no associated channels anymore
			assert_eq!(network.read_only().nodes().len(), 0);
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
				excess_data: [1; MAX_EXCESS_BYTES_FOR_RELAY + 1].to_vec()
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
				excess_data: [1; MAX_EXCESS_BYTES_FOR_RELAY + 1].to_vec(),
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

		let network = &net_graph_msg_handler.network_graph;
		let mut w = test_utils::TestVecWriter(Vec::new());
		assert!(!network.read_only().nodes().is_empty());
		assert!(!network.read_only().channels().is_empty());
		network.write(&mut w).unwrap();
		assert!(<NetworkGraph>::read(&mut io::Cursor::new(&w.0)).unwrap() == *network);
	}

	#[test]
	fn calling_sync_routing_table() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let first_blocknum = 0;
		let number_of_blocks = 0xffff_ffff;

		// It should ignore if gossip_queries feature is not enabled
		{
			let init_msg = Init { features: InitFeatures::known().clear_gossip_queries() };
			net_graph_msg_handler.sync_routing_table(&node_id_1, &init_msg);
			let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 0);
		}

		// It should send a query_channel_message with the correct information
		{
			let init_msg = Init { features: InitFeatures::known() };
			net_graph_msg_handler.sync_routing_table(&node_id_1, &init_msg);
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

		// It should not enqueue a query when should_request_full_sync return false.
		// The initial implementation allows syncing with the first 5 peers after
		// which should_request_full_sync will return false
		{
			let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
			let init_msg = Init { features: InitFeatures::known() };
			for n in 1..7 {
				let node_privkey = &SecretKey::from_slice(&[n; 32]).unwrap();
				let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);
				net_graph_msg_handler.sync_routing_table(&node_id, &init_msg);
				let events = net_graph_msg_handler.get_and_clear_pending_msg_events();
				if n <= 5 {
					assert_eq!(events.len(), 1);
				} else {
					assert_eq!(events.len(), 0);
				}

			}
		}
	}

	#[test]
	fn handling_reply_channel_range() {
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
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
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
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
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let bitcoin_key_1 = PublicKey::from_secret_key(&secp_ctx, node_1_btckey);
		let bitcoin_key_2 = PublicKey::from_secret_key(&secp_ctx, node_2_btckey);

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
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: ChannelFeatures::known(),
				chain_hash: chain_hash.clone(),
				short_channel_id: scid,
				node_id_1,
				node_id_2,
				bitcoin_key_1,
				bitcoin_key_2,
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
		net_graph_msg_handler: &NetGraphMsgHandler<Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
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
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
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

#[cfg(all(test, feature = "unstable"))]
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
