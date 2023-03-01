// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The [`NetworkGraph`] stores the network gossip and [`P2PGossipSync`] fetches it from peers

use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::hash_types::BlockHash;

use bitcoin::network::constants::Network;
use bitcoin::blockdata::constants::genesis_block;

use crate::ln::features::{ChannelFeatures, NodeFeatures, InitFeatures};
use crate::ln::msgs::{DecodeError, ErrorAction, Init, LightningError, RoutingMessageHandler, NetAddress, MAX_VALUE_MSAT};
use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate, NodeAnnouncement, GossipTimestampFilter};
use crate::ln::msgs::{QueryChannelRange, ReplyChannelRange, QueryShortChannelIds, ReplyShortChannelIdsEnd};
use crate::ln::msgs;
use crate::routing::utxo::{self, UtxoLookup};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer, MaybeReadable};
use crate::util::logger::{Logger, Level};
use crate::util::events::{MessageSendEvent, MessageSendEventsProvider};
use crate::util::scid_utils::{block_from_scid, scid_from_parts, MAX_SCID_BLOCK};
use crate::util::string::PrintableString;
use crate::util::indexed_map::{IndexedMap, Entry as IndexedMapEntry};

use crate::io;
use crate::io_extras::{copy, sink};
use crate::prelude::*;
use core::{cmp, fmt};
use crate::sync::{RwLock, RwLockReadGuard};
#[cfg(feature = "std")]
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::Mutex;
use core::ops::{Bound, Deref};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// We remove stale channel directional info two weeks after the last update, per BOLT 7's
/// suggestion.
const STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS: u64 = 60 * 60 * 24 * 14;

/// We stop tracking the removal of permanently failed nodes and channels one week after removal
const REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS: u64 = 60 * 60 * 24 * 7;

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
impl fmt::Display for NodeId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", log_bytes!(self.0))
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
pub struct NetworkGraph<L: Deref> where L::Target: Logger {
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	last_rapid_gossip_sync_timestamp: Mutex<Option<u32>>,
	genesis_hash: BlockHash,
	logger: L,
	// Lock order: channels -> nodes
	channels: RwLock<IndexedMap<u64, ChannelInfo>>,
	nodes: RwLock<IndexedMap<NodeId, NodeInfo>>,
	// Lock order: removed_channels -> removed_nodes
	//
	// NOTE: In the following `removed_*` maps, we use seconds since UNIX epoch to track time instead
	// of `std::time::Instant`s for a few reasons:
	//   * We want it to be possible to do tracking in no-std environments where we can compare
	//     a provided current UNIX timestamp with the time at which we started tracking.
	//   * In the future, if we decide to persist these maps, they will already be serializable.
	//   * Although we lose out on the platform's monotonic clock, the system clock in a std
	//     environment should be practical over the time period we are considering (on the order of a
	//     week).
	//
	/// Keeps track of short channel IDs for channels we have explicitly removed due to permanent
	/// failure so that we don't resync them from gossip. Each SCID is mapped to the time (in seconds)
	/// it was removed so that once some time passes, we can potentially resync it from gossip again.
	removed_channels: Mutex<HashMap<u64, Option<u64>>>,
	/// Keeps track of `NodeId`s we have explicitly removed due to permanent failure so that we don't
	/// resync them from gossip. Each `NodeId` is mapped to the time (in seconds) it was removed so
	/// that once some time passes, we can potentially resync it from gossip again.
	removed_nodes: Mutex<HashMap<NodeId, Option<u64>>>,
	/// Announcement messages which are awaiting an on-chain lookup to be processed.
	pub(super) pending_checks: utxo::PendingChecks,
}

/// A read-only view of [`NetworkGraph`].
pub struct ReadOnlyNetworkGraph<'a> {
	channels: RwLockReadGuard<'a, IndexedMap<u64, ChannelInfo>>,
	nodes: RwLockReadGuard<'a, IndexedMap<NodeId, NodeInfo>>,
}

/// Update to the [`NetworkGraph`] based on payment failure information conveyed via the Onion
/// return packet by a node along the route. See [BOLT #4] for details.
///
/// [BOLT #4]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkUpdate {
	/// An error indicating a `channel_update` messages should be applied via
	/// [`NetworkGraph::update_channel`].
	ChannelUpdateMessage {
		/// The update to apply via [`NetworkGraph::update_channel`].
		msg: ChannelUpdate,
	},
	/// An error indicating that a channel failed to route a payment, which should be applied via
	/// [`NetworkGraph::channel_failed`].
	ChannelFailure {
		/// The short channel id of the closed channel.
		short_channel_id: u64,
		/// Whether the channel should be permanently removed or temporarily disabled until a new
		/// `channel_update` message is received.
		is_permanent: bool,
	},
	/// An error indicating that a node failed to route a payment, which should be applied via
	/// [`NetworkGraph::node_failed_permanent`] if permanent.
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
	(2, ChannelFailure) => {
		(0, short_channel_id, required),
		(2, is_permanent, required),
	},
	(4, NodeFailure) => {
		(0, node_id, required),
		(2, is_permanent, required),
	},
);

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
pub struct P2PGossipSync<G: Deref<Target=NetworkGraph<L>>, U: Deref, L: Deref>
where U::Target: UtxoLookup, L::Target: Logger
{
	network_graph: G,
	utxo_lookup: Option<U>,
	#[cfg(feature = "std")]
	full_syncs_requested: AtomicUsize,
	pending_events: Mutex<Vec<MessageSendEvent>>,
	logger: L,
}

impl<G: Deref<Target=NetworkGraph<L>>, U: Deref, L: Deref> P2PGossipSync<G, U, L>
where U::Target: UtxoLookup, L::Target: Logger
{
	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming an existing Network Graph.
	/// UTXO lookup is used to make sure announced channels exist on-chain, channel data is
	/// correct, and the announcement is signed with channel owners' keys.
	pub fn new(network_graph: G, utxo_lookup: Option<U>, logger: L) -> Self {
		P2PGossipSync {
			network_graph,
			#[cfg(feature = "std")]
			full_syncs_requested: AtomicUsize::new(0),
			utxo_lookup,
			pending_events: Mutex::new(vec![]),
			logger,
		}
	}

	/// Adds a provider used to check new announcements. Does not affect
	/// existing announcements unless they are updated.
	/// Add, update or remove the provider would replace the current one.
	pub fn add_utxo_lookup(&mut self, utxo_lookup: Option<U>) {
		self.utxo_lookup = utxo_lookup;
	}

	/// Gets a reference to the underlying [`NetworkGraph`] which was provided in
	/// [`P2PGossipSync::new`].
	///
	/// (C-not exported) as bindings don't support a reference-to-a-reference yet
	pub fn network_graph(&self) -> &G {
		&self.network_graph
	}

	#[cfg(feature = "std")]
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

	/// Used to broadcast forward gossip messages which were validated async.
	///
	/// Note that this will ignore events other than `Broadcast*` or messages with too much excess
	/// data.
	pub(super) fn forward_gossip_msg(&self, mut ev: MessageSendEvent) {
		match &mut ev {
			MessageSendEvent::BroadcastChannelAnnouncement { msg, ref mut update_msg } => {
				if msg.contents.excess_data.len() > MAX_EXCESS_BYTES_FOR_RELAY { return; }
				if update_msg.as_ref()
					.map(|msg| msg.contents.excess_data.len()).unwrap_or(0) > MAX_EXCESS_BYTES_FOR_RELAY
				{
					*update_msg = None;
				}
			},
			MessageSendEvent::BroadcastChannelUpdate { msg } => {
				if msg.contents.excess_data.len() > MAX_EXCESS_BYTES_FOR_RELAY { return; }
			},
			MessageSendEvent::BroadcastNodeAnnouncement { msg } => {
				if msg.contents.excess_data.len() >  MAX_EXCESS_BYTES_FOR_RELAY ||
				   msg.contents.excess_address_data.len() > MAX_EXCESS_BYTES_FOR_RELAY ||
				   msg.contents.excess_data.len() + msg.contents.excess_address_data.len() > MAX_EXCESS_BYTES_FOR_RELAY
				{
					return;
				}
			},
			_ => return,
		}
		self.pending_events.lock().unwrap().push(ev);
	}
}

impl<L: Deref> NetworkGraph<L> where L::Target: Logger {
	/// Handles any network updates originating from [`Event`]s.
	///
	/// [`Event`]: crate::util::events::Event
	pub fn handle_network_update(&self, network_update: &NetworkUpdate) {
		match *network_update {
			NetworkUpdate::ChannelUpdateMessage { ref msg } => {
				let short_channel_id = msg.contents.short_channel_id;
				let is_enabled = msg.contents.flags & (1 << 1) != (1 << 1);
				let status = if is_enabled { "enabled" } else { "disabled" };
				log_debug!(self.logger, "Updating channel with channel_update from a payment failure. Channel {} is {}.", short_channel_id, status);
				let _ = self.update_channel(msg);
			},
			NetworkUpdate::ChannelFailure { short_channel_id, is_permanent } => {
				let action = if is_permanent { "Removing" } else { "Disabling" };
				log_debug!(self.logger, "{} channel graph entry for {} due to a payment failure.", action, short_channel_id);
				self.channel_failed(short_channel_id, is_permanent);
			},
			NetworkUpdate::NodeFailure { ref node_id, is_permanent } => {
				if is_permanent {
					log_debug!(self.logger,
						"Removed node graph entry for {} due to a payment failure.", log_pubkey!(node_id));
					self.node_failed_permanent(node_id);
				};
			},
		}
	}
}

macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr, $msg_type: expr ) => {
		match $secp_ctx.verify_ecdsa($msg, $sig, $pubkey) {
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

macro_rules! get_pubkey_from_node_id {
	( $node_id: expr, $msg_type: expr ) => {
		PublicKey::from_slice($node_id.as_slice())
			.map_err(|_| LightningError {
				err: format!("Invalid public key on {} message", $msg_type),
				action: ErrorAction::SendWarningMessage {
					msg: msgs::WarningMessage {
						channel_id: [0; 32],
						data: format!("Invalid public key on {} message", $msg_type),
					},
					log_level: Level::Trace
				}
			})?
	}
}

impl<G: Deref<Target=NetworkGraph<L>>, U: Deref, L: Deref> RoutingMessageHandler for P2PGossipSync<G, U, L>
where U::Target: UtxoLookup, L::Target: Logger
{
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_node_from_announcement(msg)?;
		Ok(msg.contents.excess_data.len() <=  MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY &&
		   msg.contents.excess_data.len() + msg.contents.excess_address_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.update_channel_from_announcement(msg, &self.utxo_lookup)?;
		Ok(msg.contents.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
		self.network_graph.update_channel(msg)?;
		Ok(msg.contents.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY)
	}

	fn get_next_channel_announcement(&self, starting_point: u64) -> Option<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)> {
		let mut channels = self.network_graph.channels.write().unwrap();
		for (_, ref chan) in channels.range(starting_point..) {
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
				return Some((chan_announcement, one_to_two_announcement, two_to_one_announcement));
			} else {
				// TODO: We may end up sending un-announced channel_updates if we are sending
				// initial sync data while receiving announce/updates for this channel.
			}
		}
		None
	}

	fn get_next_node_announcement(&self, starting_point: Option<&NodeId>) -> Option<NodeAnnouncement> {
		let mut nodes = self.network_graph.nodes.write().unwrap();
		let iter = if let Some(node_id) = starting_point {
				nodes.range((Bound::Excluded(node_id), Bound::Unbounded))
			} else {
				nodes.range(..)
			};
		for (_, ref node) in iter {
			if let Some(node_info) = node.announcement_info.as_ref() {
				if let Some(msg) = node_info.announcement_message.clone() {
					return Some(msg);
				}
			}
		}
		None
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
	fn peer_connected(&self, their_node_id: &PublicKey, init_msg: &Init, _inbound: bool) -> Result<(), ()> {
		// We will only perform a sync with peers that support gossip_queries.
		if !init_msg.features.supports_gossip_queries() {
			// Don't disconnect peers for not supporting gossip queries. We may wish to have
			// channels with peers even without being able to exchange gossip.
			return Ok(());
		}

		// The lightning network's gossip sync system is completely broken in numerous ways.
		//
		// Given no broadly-available set-reconciliation protocol, the only reasonable approach is
		// to do a full sync from the first few peers we connect to, and then receive gossip
		// updates from all our peers normally.
		//
		// Originally, we could simply tell a peer to dump us the entire gossip table on startup,
		// wasting lots of bandwidth but ensuring we have the full network graph. After the initial
		// dump peers would always send gossip and we'd stay up-to-date with whatever our peer has
		// seen.
		//
		// In order to reduce the bandwidth waste, "gossip queries" were introduced, allowing you
		// to ask for the SCIDs of all channels in your peer's routing graph, and then only request
		// channel data which you are missing. Except there was no way at all to identify which
		// `channel_update`s you were missing, so you still had to request everything, just in a
		// very complicated way with some queries instead of just getting the dump.
		//
		// Later, an option was added to fetch the latest timestamps of the `channel_update`s to
		// make efficient sync possible, however it has yet to be implemented in lnd, which makes
		// relying on it useless.
		//
		// After gossip queries were introduced, support for receiving a full gossip table dump on
		// connection was removed from several nodes, making it impossible to get a full sync
		// without using the "gossip queries" messages.
		//
		// Once you opt into "gossip queries" the only way to receive any gossip updates that a
		// peer receives after you connect, you must send a `gossip_timestamp_filter` message. This
		// message, as the name implies, tells the peer to not forward any gossip messages with a
		// timestamp older than a given value (not the time the peer received the filter, but the
		// timestamp in the update message, which is often hours behind when the peer received the
		// message).
		//
		// Obnoxiously, `gossip_timestamp_filter` isn't *just* a filter, but its also a request for
		// your peer to send you the full routing graph (subject to the filter). Thus, in order to
		// tell a peer to send you any updates as it sees them, you have to also ask for the full
		// routing graph to be synced. If you set a timestamp filter near the current time, peers
		// will simply not forward any new updates they see to you which were generated some time
		// ago (which is not uncommon). If you instead set a timestamp filter near 0 (or two weeks
		// ago), you will always get the full routing graph from all your peers.
		//
		// Most lightning nodes today opt to simply turn off receiving gossip data which only
		// propagated some time after it was generated, and, worse, often disable gossiping with
		// several peers after their first connection. The second behavior can cause gossip to not
		// propagate fully if there are cuts in the gossiping subgraph.
		//
		// In an attempt to cut a middle ground between always fetching the full graph from all of
		// our peers and never receiving gossip from peers at all, we send all of our peers a
		// `gossip_timestamp_filter`, with the filter time set either two weeks ago or an hour ago.
		//
		// For no-std builds, we bury our head in the sand and do a full sync on each connection.
		#[allow(unused_mut, unused_assignments)]
		let mut gossip_start_time = 0;
		#[cfg(feature = "std")]
		{
			gossip_start_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			if self.should_request_full_sync(&their_node_id) {
				gossip_start_time -= 60 * 60 * 24 * 7 * 2; // 2 weeks ago
			} else {
				gossip_start_time -= 60 * 60; // an hour ago
			}
		}

		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(MessageSendEvent::SendGossipTimestampFilter {
			node_id: their_node_id.clone(),
			msg: GossipTimestampFilter {
				chain_hash: self.network_graph.genesis_hash,
				first_timestamp: gossip_start_time as u32, // 2106 issue!
				timestamp_range: u32::max_value(),
			},
		});
		Ok(())
	}

	fn handle_reply_channel_range(&self, _their_node_id: &PublicKey, _msg: ReplyChannelRange) -> Result<(), LightningError> {
		// We don't make queries, so should never receive replies. If, in the future, the set
		// reconciliation extensions to gossip queries become broadly supported, we should revert
		// this code to its state pre-0.0.106.
		Ok(())
	}

	fn handle_reply_short_channel_ids_end(&self, _their_node_id: &PublicKey, _msg: ReplyShortChannelIdsEnd) -> Result<(), LightningError> {
		// We don't make queries, so should never receive replies. If, in the future, the set
		// reconciliation extensions to gossip queries become broadly supported, we should revert
		// this code to its state pre-0.0.106.
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
		let mut channels = self.network_graph.channels.write().unwrap();
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

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn processing_queue_high(&self) -> bool {
		self.network_graph.pending_checks.too_many_checks_pending()
	}
}

impl<G: Deref<Target=NetworkGraph<L>>, U: Deref, L: Deref> MessageSendEventsProvider for P2PGossipSync<G, U, L>
where
	U::Target: UtxoLookup,
	L::Target: Logger,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		core::mem::swap(&mut ret, &mut pending_events);
		ret
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
	pub htlc_maximum_msat: u64,
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

impl Writeable for ChannelUpdateInfo {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.last_update, required),
			(2, self.enabled, required),
			(4, self.cltv_expiry_delta, required),
			(6, self.htlc_minimum_msat, required),
			// Writing htlc_maximum_msat as an Option<u64> is required to maintain backwards
			// compatibility with LDK versions prior to v0.0.110.
			(8, Some(self.htlc_maximum_msat), required),
			(10, self.fees, required),
			(12, self.last_update_message, required),
		});
		Ok(())
	}
}

impl Readable for ChannelUpdateInfo {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_tlv_field_var!(last_update, required);
		_init_tlv_field_var!(enabled, required);
		_init_tlv_field_var!(cltv_expiry_delta, required);
		_init_tlv_field_var!(htlc_minimum_msat, required);
		_init_tlv_field_var!(htlc_maximum_msat, option);
		_init_tlv_field_var!(fees, required);
		_init_tlv_field_var!(last_update_message, required);

		read_tlv_fields!(reader, {
			(0, last_update, required),
			(2, enabled, required),
			(4, cltv_expiry_delta, required),
			(6, htlc_minimum_msat, required),
			(8, htlc_maximum_msat, required),
			(10, fees, required),
			(12, last_update_message, required)
		});

		if let Some(htlc_maximum_msat) = htlc_maximum_msat {
			Ok(ChannelUpdateInfo {
				last_update: _init_tlv_based_struct_field!(last_update, required),
				enabled: _init_tlv_based_struct_field!(enabled, required),
				cltv_expiry_delta: _init_tlv_based_struct_field!(cltv_expiry_delta, required),
				htlc_minimum_msat: _init_tlv_based_struct_field!(htlc_minimum_msat, required),
				htlc_maximum_msat,
				fees: _init_tlv_based_struct_field!(fees, required),
				last_update_message: _init_tlv_based_struct_field!(last_update_message, required),
			})
		} else {
			Err(DecodeError::InvalidValue)
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
		direction.map(|dir| (DirectedChannelInfo::new(self, dir), source))
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
		direction.map(|dir| (DirectedChannelInfo::new(self, dir), target))
	}

	/// Returns a [`ChannelUpdateInfo`] based on the direction implied by the channel_flag.
	pub fn get_directional_info(&self, channel_flags: u8) -> Option<&ChannelUpdateInfo> {
		let direction = channel_flags & 1u8;
		if direction == 0 {
			self.one_to_two.as_ref()
		} else {
			self.two_to_one.as_ref()
		}
	}
}

impl fmt::Display for ChannelInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "features: {}, node_one: {}, one_to_two: {:?}, node_two: {}, two_to_one: {:?}",
		   log_bytes!(self.features.encode()), log_bytes!(self.node_one.as_slice()), self.one_to_two, log_bytes!(self.node_two.as_slice()), self.two_to_one)?;
		Ok(())
	}
}

impl Writeable for ChannelInfo {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.features, required),
			(1, self.announcement_received_time, (default_value, 0)),
			(2, self.node_one, required),
			(4, self.one_to_two, required),
			(6, self.node_two, required),
			(8, self.two_to_one, required),
			(10, self.capacity_sats, required),
			(12, self.announcement_message, required),
		});
		Ok(())
	}
}

// A wrapper allowing for the optional deseralization of ChannelUpdateInfo. Utilizing this is
// necessary to maintain backwards compatibility with previous serializations of `ChannelUpdateInfo`
// that may have no `htlc_maximum_msat` field set. In case the field is absent, we simply ignore
// the error and continue reading the `ChannelInfo`. Hopefully, we'll then eventually receive newer
// channel updates via the gossip network.
struct ChannelUpdateInfoDeserWrapper(Option<ChannelUpdateInfo>);

impl MaybeReadable for ChannelUpdateInfoDeserWrapper {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		match crate::util::ser::Readable::read(reader) {
			Ok(channel_update_option) => Ok(Some(Self(channel_update_option))),
			Err(DecodeError::ShortRead) => Ok(None),
			Err(DecodeError::InvalidValue) => Ok(None),
			Err(err) => Err(err),
		}
	}
}

impl Readable for ChannelInfo {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_tlv_field_var!(features, required);
		_init_tlv_field_var!(announcement_received_time, (default_value, 0));
		_init_tlv_field_var!(node_one, required);
		let mut one_to_two_wrap: Option<ChannelUpdateInfoDeserWrapper> = None;
		_init_tlv_field_var!(node_two, required);
		let mut two_to_one_wrap: Option<ChannelUpdateInfoDeserWrapper> = None;
		_init_tlv_field_var!(capacity_sats, required);
		_init_tlv_field_var!(announcement_message, required);
		read_tlv_fields!(reader, {
			(0, features, required),
			(1, announcement_received_time, (default_value, 0)),
			(2, node_one, required),
			(4, one_to_two_wrap, upgradable_option),
			(6, node_two, required),
			(8, two_to_one_wrap, upgradable_option),
			(10, capacity_sats, required),
			(12, announcement_message, required),
		});

		Ok(ChannelInfo {
			features: _init_tlv_based_struct_field!(features, required),
			node_one: _init_tlv_based_struct_field!(node_one, required),
			one_to_two: one_to_two_wrap.map(|w| w.0).unwrap_or(None),
			node_two: _init_tlv_based_struct_field!(node_two, required),
			two_to_one: two_to_one_wrap.map(|w| w.0).unwrap_or(None),
			capacity_sats: _init_tlv_based_struct_field!(capacity_sats, required),
			announcement_message: _init_tlv_based_struct_field!(announcement_message, required),
			announcement_received_time: _init_tlv_based_struct_field!(announcement_received_time, (default_value, 0)),
		})
	}
}

/// A wrapper around [`ChannelInfo`] representing information about the channel as directed from a
/// source node to a target node.
#[derive(Clone)]
pub struct DirectedChannelInfo<'a> {
	channel: &'a ChannelInfo,
	direction: &'a ChannelUpdateInfo,
	htlc_maximum_msat: u64,
	effective_capacity: EffectiveCapacity,
}

impl<'a> DirectedChannelInfo<'a> {
	#[inline]
	fn new(channel: &'a ChannelInfo, direction: &'a ChannelUpdateInfo) -> Self {
		let mut htlc_maximum_msat = direction.htlc_maximum_msat;
		let capacity_msat = channel.capacity_sats.map(|capacity_sats| capacity_sats * 1000);

		let effective_capacity = match capacity_msat {
			Some(capacity_msat) => {
				htlc_maximum_msat = cmp::min(htlc_maximum_msat, capacity_msat);
				EffectiveCapacity::Total { capacity_msat, htlc_maximum_msat: htlc_maximum_msat }
			},
			None => EffectiveCapacity::MaximumHTLC { amount_msat: htlc_maximum_msat },
		};

		Self {
			channel, direction, htlc_maximum_msat, effective_capacity
		}
	}

	/// Returns information for the channel.
	#[inline]
	pub fn channel(&self) -> &'a ChannelInfo { self.channel }

	/// Returns the maximum HTLC amount allowed over the channel in the direction.
	#[inline]
	pub fn htlc_maximum_msat(&self) -> u64 {
		self.htlc_maximum_msat
	}

	/// Returns the [`EffectiveCapacity`] of the channel in the direction.
	///
	/// This is either the total capacity from the funding transaction, if known, or the
	/// `htlc_maximum_msat` for the direction as advertised by the gossip network, if known,
	/// otherwise.
	pub fn effective_capacity(&self) -> EffectiveCapacity {
		self.effective_capacity
	}

	/// Returns information for the direction.
	#[inline]
	pub(super) fn direction(&self) -> &'a ChannelUpdateInfo { self.direction }
}

impl<'a> fmt::Debug for DirectedChannelInfo<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		f.debug_struct("DirectedChannelInfo")
			.field("channel", &self.channel)
			.finish()
	}
}

/// The effective capacity of a channel for routing purposes.
///
/// While this may be smaller than the actual channel capacity, amounts greater than
/// [`Self::as_msat`] should not be routed through the channel.
#[derive(Clone, Copy, Debug, PartialEq)]
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
		/// The maximum HTLC amount denominated in millisatoshi.
		htlc_maximum_msat: u64
	},
	/// A capacity sufficient to route any payment, typically used for private channels provided by
	/// an invoice.
	Infinite,
	/// A capacity that is unknown possibly because either the chain state is unavailable to know
	/// the total capacity or the `htlc_maximum_msat` was not advertised on the gossip network.
	Unknown,
}

/// The presumed channel capacity denominated in millisatoshi for [`EffectiveCapacity::Unknown`] to
/// use when making routing decisions.
pub const UNKNOWN_CHANNEL_CAPACITY_MSAT: u64 = 250_000 * 1000;

impl EffectiveCapacity {
	/// Returns the effective capacity denominated in millisatoshi.
	pub fn as_msat(&self) -> u64 {
		match self {
			EffectiveCapacity::ExactLiquidity { liquidity_msat } => *liquidity_msat,
			EffectiveCapacity::MaximumHTLC { amount_msat } => *amount_msat,
			EffectiveCapacity::Total { capacity_msat, .. } => *capacity_msat,
			EffectiveCapacity::Infinite => u64::max_value(),
			EffectiveCapacity::Unknown => UNKNOWN_CHANNEL_CAPACITY_MSAT,
		}
	}
}

/// Fees for routing via a given channel or a node
#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct RoutingFees {
	/// Flat routing fee in millisatoshis.
	pub base_msat: u32,
	/// Liquidity-based routing fee in millionths of a routed amount.
	/// In other words, 10000 is 1%.
	pub proportional_millionths: u32,
}

impl_writeable_tlv_based!(RoutingFees, {
	(0, base_msat, required),
	(2, proportional_millionths, required)
});

#[derive(Clone, Debug, PartialEq, Eq)]
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
	pub alias: NodeAlias,
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

/// A user-defined name for a node, which may be used when displaying the node in a graph.
///
/// Since node aliases are provided by third parties, they are a potential avenue for injection
/// attacks. Care must be taken when processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAlias(pub [u8; 32]);

impl fmt::Display for NodeAlias {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		let first_null = self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len());
		let bytes = self.0.split_at(first_null).0;
		match core::str::from_utf8(bytes) {
			Ok(alias) => PrintableString(alias).fmt(f)?,
			Err(_) => {
				use core::fmt::Write;
				for c in bytes.iter().map(|b| *b as char) {
					// Display printable ASCII characters
					let control_symbol = core::char::REPLACEMENT_CHARACTER;
					let c = if c >= '\x20' && c <= '\x7e' { c } else { control_symbol };
					f.write_char(c)?;
				}
			},
		};
		Ok(())
	}
}

impl Writeable for NodeAlias {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for NodeAlias {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(NodeAlias(Readable::read(r)?))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Details about a node in the network, known from the network announcement.
pub struct NodeInfo {
	/// All valid channels a node has announced
	pub channels: Vec<u64>,
	/// More information about a node from node_announcement.
	/// Optional because we store a Node entry after learning about it from
	/// a channel announcement, but before receiving a node announcement.
	pub announcement_info: Option<NodeAnnouncementInfo>
}

impl fmt::Display for NodeInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, " channels: {:?}, announcement_info: {:?}",
			&self.channels[..], self.announcement_info)?;
		Ok(())
	}
}

impl Writeable for NodeInfo {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			// Note that older versions of LDK wrote the lowest inbound fees here at type 0
			(2, self.announcement_info, option),
			(4, self.channels, vec_type),
		});
		Ok(())
	}
}

// A wrapper allowing for the optional deseralization of `NodeAnnouncementInfo`. Utilizing this is
// necessary to maintain compatibility with previous serializations of `NetAddress` that have an
// invalid hostname set. We ignore and eat all errors until we are either able to read a
// `NodeAnnouncementInfo` or hit a `ShortRead`, i.e., read the TLV field to the end.
struct NodeAnnouncementInfoDeserWrapper(NodeAnnouncementInfo);

impl MaybeReadable for NodeAnnouncementInfoDeserWrapper {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		match crate::util::ser::Readable::read(reader) {
			Ok(node_announcement_info) => return Ok(Some(Self(node_announcement_info))),
			Err(_) => {
				copy(reader, &mut sink()).unwrap();
				return Ok(None)
			},
		};
	}
}

impl Readable for NodeInfo {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		// Historically, we tracked the lowest inbound fees for any node in order to use it as an
		// A* heuristic when routing. Sadly, these days many, many nodes have at least one channel
		// with zero inbound fees, causing that heuristic to provide little gain. Worse, because it
		// requires additional complexity and lookups during routing, it ends up being a
		// performance loss. Thus, we simply ignore the old field here and no longer track it.
		let mut _lowest_inbound_channel_fees: Option<RoutingFees> = None;
		let mut announcement_info_wrap: Option<NodeAnnouncementInfoDeserWrapper> = None;
		_init_tlv_field_var!(channels, vec_type);

		read_tlv_fields!(reader, {
			(0, _lowest_inbound_channel_fees, option),
			(2, announcement_info_wrap, upgradable_option),
			(4, channels, vec_type),
		});

		Ok(NodeInfo {
			announcement_info: announcement_info_wrap.map(|w| w.0),
			channels: _init_tlv_based_struct_field!(channels, vec_type),
		})
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl<L: Deref> Writeable for NetworkGraph<L> where L::Target: Logger {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.genesis_hash.write(writer)?;
		let channels = self.channels.read().unwrap();
		(channels.len() as u64).write(writer)?;
		for (ref chan_id, ref chan_info) in channels.unordered_iter() {
			(*chan_id).write(writer)?;
			chan_info.write(writer)?;
		}
		let nodes = self.nodes.read().unwrap();
		(nodes.len() as u64).write(writer)?;
		for (ref node_id, ref node_info) in nodes.unordered_iter() {
			node_id.write(writer)?;
			node_info.write(writer)?;
		}

		let last_rapid_gossip_sync_timestamp = self.get_last_rapid_gossip_sync_timestamp();
		write_tlv_fields!(writer, {
			(1, last_rapid_gossip_sync_timestamp, option),
		});
		Ok(())
	}
}

impl<L: Deref> ReadableArgs<L> for NetworkGraph<L> where L::Target: Logger {
	fn read<R: io::Read>(reader: &mut R, logger: L) -> Result<NetworkGraph<L>, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let genesis_hash: BlockHash = Readable::read(reader)?;
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = IndexedMap::new();
		for _ in 0..channels_count {
			let chan_id: u64 = Readable::read(reader)?;
			let chan_info = Readable::read(reader)?;
			channels.insert(chan_id, chan_info);
		}
		let nodes_count: u64 = Readable::read(reader)?;
		let mut nodes = IndexedMap::new();
		for _ in 0..nodes_count {
			let node_id = Readable::read(reader)?;
			let node_info = Readable::read(reader)?;
			nodes.insert(node_id, node_info);
		}

		let mut last_rapid_gossip_sync_timestamp: Option<u32> = None;
		read_tlv_fields!(reader, {
			(1, last_rapid_gossip_sync_timestamp, option),
		});

		Ok(NetworkGraph {
			secp_ctx: Secp256k1::verification_only(),
			genesis_hash,
			logger,
			channels: RwLock::new(channels),
			nodes: RwLock::new(nodes),
			last_rapid_gossip_sync_timestamp: Mutex::new(last_rapid_gossip_sync_timestamp),
			removed_nodes: Mutex::new(HashMap::new()),
			removed_channels: Mutex::new(HashMap::new()),
			pending_checks: utxo::PendingChecks::new(),
		})
	}
}

impl<L: Deref> fmt::Display for NetworkGraph<L> where L::Target: Logger {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "Network map\n[Channels]")?;
		for (key, val) in self.channels.read().unwrap().unordered_iter() {
			writeln!(f, " {}: {}", key, val)?;
		}
		writeln!(f, "[Nodes]")?;
		for (&node_id, val) in self.nodes.read().unwrap().unordered_iter() {
			writeln!(f, " {}: {}", log_bytes!(node_id.as_slice()), val)?;
		}
		Ok(())
	}
}

impl<L: Deref> Eq for NetworkGraph<L> where L::Target: Logger {}
impl<L: Deref> PartialEq for NetworkGraph<L> where L::Target: Logger {
	fn eq(&self, other: &Self) -> bool {
		self.genesis_hash == other.genesis_hash &&
			*self.channels.read().unwrap() == *other.channels.read().unwrap() &&
			*self.nodes.read().unwrap() == *other.nodes.read().unwrap()
	}
}

impl<L: Deref> NetworkGraph<L> where L::Target: Logger {
	/// Creates a new, empty, network graph.
	pub fn new(network: Network, logger: L) -> NetworkGraph<L> {
		Self {
			secp_ctx: Secp256k1::verification_only(),
			genesis_hash: genesis_block(network).header.block_hash(),
			logger,
			channels: RwLock::new(IndexedMap::new()),
			nodes: RwLock::new(IndexedMap::new()),
			last_rapid_gossip_sync_timestamp: Mutex::new(None),
			removed_channels: Mutex::new(HashMap::new()),
			removed_nodes: Mutex::new(HashMap::new()),
			pending_checks: utxo::PendingChecks::new(),
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

	/// The unix timestamp provided by the most recent rapid gossip sync.
	/// It will be set by the rapid sync process after every sync completion.
	pub fn get_last_rapid_gossip_sync_timestamp(&self) -> Option<u32> {
		self.last_rapid_gossip_sync_timestamp.lock().unwrap().clone()
	}

	/// Update the unix timestamp provided by the most recent rapid gossip sync.
	/// This should be done automatically by the rapid sync process after every sync completion.
	pub fn set_last_rapid_gossip_sync_timestamp(&self, last_rapid_gossip_sync_timestamp: u32) {
		self.last_rapid_gossip_sync_timestamp.lock().unwrap().replace(last_rapid_gossip_sync_timestamp);
	}

	/// Clears the `NodeAnnouncementInfo` field for all nodes in the `NetworkGraph` for testing
	/// purposes.
	#[cfg(test)]
	pub fn clear_nodes_announcement_info(&self) {
		for node in self.nodes.write().unwrap().unordered_iter_mut() {
			node.1.announcement_info = None;
		}
	}

	/// For an already known node (from channel announcements), update its stored properties from a
	/// given node announcement.
	///
	/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	pub fn update_node_from_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<(), LightningError> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.signature, &get_pubkey_from_node_id!(msg.contents.node_id, "node_announcement"), "node_announcement");
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
		let mut nodes = self.nodes.write().unwrap();
		match nodes.get_mut(&msg.node_id) {
			None => {
				core::mem::drop(nodes);
				self.pending_checks.check_hold_pending_node_announcement(msg, full_msg)?;
				Err(LightningError{err: "No existing channels for node_announcement".to_owned(), action: ErrorAction::IgnoreError})
			},
			Some(node) => {
				if let Some(node_info) = node.announcement_info.as_ref() {
					// The timestamp field is somewhat of a misnomer - the BOLTs use it to order
					// updates to ensure you always have the latest one, only vaguely suggesting
					// that it be at least the current time.
					if node_info.last_update  > msg.timestamp {
						return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
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
					alias: NodeAlias(msg.alias),
					addresses: msg.addresses.clone(),
					announcement_message: if should_relay { full_msg.cloned() } else { None },
				});

				Ok(())
			}
		}
	}

	/// Store or update channel info from a channel announcement.
	///
	/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	///
	/// If a [`UtxoLookup`] object is provided via `utxo_lookup`, it will be called to verify
	/// the corresponding UTXO exists on chain and is correctly-formatted.
	pub fn update_channel_from_announcement<U: Deref>(
		&self, msg: &msgs::ChannelAnnouncement, utxo_lookup: &Option<U>,
	) -> Result<(), LightningError>
	where
		U::Target: UtxoLookup,
	{
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.node_signature_1, &get_pubkey_from_node_id!(msg.contents.node_id_1, "channel_announcement"), "channel_announcement");
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.node_signature_2, &get_pubkey_from_node_id!(msg.contents.node_id_2, "channel_announcement"), "channel_announcement");
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.bitcoin_signature_1, &get_pubkey_from_node_id!(msg.contents.bitcoin_key_1, "channel_announcement"), "channel_announcement");
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.bitcoin_signature_2, &get_pubkey_from_node_id!(msg.contents.bitcoin_key_2, "channel_announcement"), "channel_announcement");
		self.update_channel_from_unsigned_announcement_intern(&msg.contents, Some(msg), utxo_lookup)
	}

	/// Store or update channel info from a channel announcement without verifying the associated
	/// signatures. Because we aren't given the associated signatures here we cannot relay the
	/// channel announcement to any of our peers.
	///
	/// If a [`UtxoLookup`] object is provided via `utxo_lookup`, it will be called to verify
	/// the corresponding UTXO exists on chain and is correctly-formatted.
	pub fn update_channel_from_unsigned_announcement<U: Deref>(
		&self, msg: &msgs::UnsignedChannelAnnouncement, utxo_lookup: &Option<U>
	) -> Result<(), LightningError>
	where
		U::Target: UtxoLookup,
	{
		self.update_channel_from_unsigned_announcement_intern(msg, None, utxo_lookup)
	}

	/// Update channel from partial announcement data received via rapid gossip sync
	///
	/// `timestamp: u64`: Timestamp emulating the backdated original announcement receipt (by the
	/// rapid gossip sync server)
	///
	/// All other parameters as used in [`msgs::UnsignedChannelAnnouncement`] fields.
	pub fn add_channel_from_partial_announcement(&self, short_channel_id: u64, timestamp: u64, features: ChannelFeatures, node_id_1: PublicKey, node_id_2: PublicKey) -> Result<(), LightningError> {
		if node_id_1 == node_id_2 {
			return Err(LightningError{err: "Channel announcement node had a channel with itself".to_owned(), action: ErrorAction::IgnoreError});
		};

		let node_1 = NodeId::from_pubkey(&node_id_1);
		let node_2 = NodeId::from_pubkey(&node_id_2);
		let channel_info = ChannelInfo {
			features,
			node_one: node_1.clone(),
			one_to_two: None,
			node_two: node_2.clone(),
			two_to_one: None,
			capacity_sats: None,
			announcement_message: None,
			announcement_received_time: timestamp,
		};

		self.add_channel_between_nodes(short_channel_id, channel_info, None)
	}

	fn add_channel_between_nodes(&self, short_channel_id: u64, channel_info: ChannelInfo, utxo_value: Option<u64>) -> Result<(), LightningError> {
		let mut channels = self.channels.write().unwrap();
		let mut nodes = self.nodes.write().unwrap();

		let node_id_a = channel_info.node_one.clone();
		let node_id_b = channel_info.node_two.clone();

		match channels.entry(short_channel_id) {
			IndexedMapEntry::Occupied(mut entry) => {
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
					Self::remove_channel_in_nodes(&mut nodes, &entry.get(), short_channel_id);
					*entry.get_mut() = channel_info;
				} else {
					return Err(LightningError{err: "Already have knowledge of channel".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
				}
			},
			IndexedMapEntry::Vacant(entry) => {
				entry.insert(channel_info);
			}
		};

		for current_node_id in [node_id_a, node_id_b].iter() {
			match nodes.entry(current_node_id.clone()) {
				IndexedMapEntry::Occupied(node_entry) => {
					node_entry.into_mut().channels.push(short_channel_id);
				},
				IndexedMapEntry::Vacant(node_entry) => {
					node_entry.insert(NodeInfo {
						channels: vec!(short_channel_id),
						announcement_info: None,
					});
				}
			};
		};

		Ok(())
	}

	fn update_channel_from_unsigned_announcement_intern<U: Deref>(
		&self, msg: &msgs::UnsignedChannelAnnouncement, full_msg: Option<&msgs::ChannelAnnouncement>, utxo_lookup: &Option<U>
	) -> Result<(), LightningError>
	where
		U::Target: UtxoLookup,
	{
		if msg.node_id_1 == msg.node_id_2 || msg.bitcoin_key_1 == msg.bitcoin_key_2 {
			return Err(LightningError{err: "Channel announcement node had a channel with itself".to_owned(), action: ErrorAction::IgnoreError});
		}

		{
			let channels = self.channels.read().unwrap();

			if let Some(chan) = channels.get(&msg.short_channel_id) {
				if chan.capacity_sats.is_some() {
					// If we'd previously looked up the channel on-chain and checked the script
					// against what appears on-chain, ignore the duplicate announcement.
					//
					// Because a reorg could replace one channel with another at the same SCID, if
					// the channel appears to be different, we re-validate. This doesn't expose us
					// to any more DoS risk than not, as a peer can always flood us with
					// randomly-generated SCID values anyway.
					//
					// We use the Node IDs rather than the bitcoin_keys to check for "equivalence"
					// as we didn't (necessarily) store the bitcoin keys, and we only really care
					// if the peers on the channel changed anyway.
					if msg.node_id_1 == chan.node_one && msg.node_id_2 == chan.node_two {
						return Err(LightningError {
							err: "Already have chain-validated channel".to_owned(),
							action: ErrorAction::IgnoreDuplicateGossip
						});
					}
				} else if utxo_lookup.is_none() {
					// Similarly, if we can't check the chain right now anyway, ignore the
					// duplicate announcement without bothering to take the channels write lock.
					return Err(LightningError {
						err: "Already have non-chain-validated channel".to_owned(),
						action: ErrorAction::IgnoreDuplicateGossip
					});
				}
			}
		}

		{
			let removed_channels = self.removed_channels.lock().unwrap();
			let removed_nodes = self.removed_nodes.lock().unwrap();
			if removed_channels.contains_key(&msg.short_channel_id) ||
				removed_nodes.contains_key(&msg.node_id_1) ||
				removed_nodes.contains_key(&msg.node_id_2) {
				return Err(LightningError{
					err: format!("Channel with SCID {} or one of its nodes was removed from our network graph recently", &msg.short_channel_id),
					action: ErrorAction::IgnoreAndLog(Level::Gossip)});
			}
		}

		let utxo_value = self.pending_checks.check_channel_announcement(
			utxo_lookup, msg, full_msg)?;

		#[allow(unused_mut, unused_assignments)]
		let mut announcement_received_time = 0;
		#[cfg(feature = "std")]
		{
			announcement_received_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
		}

		let chan_info = ChannelInfo {
			features: msg.features.clone(),
			node_one: msg.node_id_1,
			one_to_two: None,
			node_two: msg.node_id_2,
			two_to_one: None,
			capacity_sats: utxo_value,
			announcement_message: if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
				{ full_msg.cloned() } else { None },
			announcement_received_time,
		};

		self.add_channel_between_nodes(msg.short_channel_id, chan_info, utxo_value)?;

		log_gossip!(self.logger, "Added channel_announcement for {}{}", msg.short_channel_id, if !msg.excess_data.is_empty() { " with excess uninterpreted data!" } else { "" });
		Ok(())
	}

	/// Marks a channel in the graph as failed if a corresponding HTLC fail was sent.
	/// If permanent, removes a channel from the local storage.
	/// May cause the removal of nodes too, if this was their last channel.
	/// If not permanent, makes channels unavailable for routing.
	pub fn channel_failed(&self, short_channel_id: u64, is_permanent: bool) {
		#[cfg(feature = "std")]
		let current_time_unix = Some(SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
		#[cfg(not(feature = "std"))]
		let current_time_unix = None;

		self.channel_failed_with_time(short_channel_id, is_permanent, current_time_unix)
	}

	/// Marks a channel in the graph as failed if a corresponding HTLC fail was sent.
	/// If permanent, removes a channel from the local storage.
	/// May cause the removal of nodes too, if this was their last channel.
	/// If not permanent, makes channels unavailable for routing.
	fn channel_failed_with_time(&self, short_channel_id: u64, is_permanent: bool, current_time_unix: Option<u64>) {
		let mut channels = self.channels.write().unwrap();
		if is_permanent {
			if let Some(chan) = channels.remove(&short_channel_id) {
				let mut nodes = self.nodes.write().unwrap();
				self.removed_channels.lock().unwrap().insert(short_channel_id, current_time_unix);
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

	/// Marks a node in the graph as permanently failed, effectively removing it and its channels
	/// from local storage.
	pub fn node_failed_permanent(&self, node_id: &PublicKey) {
		#[cfg(feature = "std")]
		let current_time_unix = Some(SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs());
		#[cfg(not(feature = "std"))]
		let current_time_unix = None;

		let node_id = NodeId::from_pubkey(node_id);
		let mut channels = self.channels.write().unwrap();
		let mut nodes = self.nodes.write().unwrap();
		let mut removed_channels = self.removed_channels.lock().unwrap();
		let mut removed_nodes = self.removed_nodes.lock().unwrap();

		if let Some(node) = nodes.remove(&node_id) {
			for scid in node.channels.iter() {
				if let Some(chan_info) = channels.remove(scid) {
					let other_node_id = if node_id == chan_info.node_one { chan_info.node_two } else { chan_info.node_one };
					if let IndexedMapEntry::Occupied(mut other_node_entry) = nodes.entry(other_node_id) {
						other_node_entry.get_mut().channels.retain(|chan_id| {
							*scid != *chan_id
						});
						if other_node_entry.get().channels.is_empty() {
							other_node_entry.remove_entry();
						}
					}
					removed_channels.insert(*scid, current_time_unix);
				}
			}
			removed_nodes.insert(node_id, current_time_unix);
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
	/// This method will also cause us to stop tracking removed nodes and channels if they have been
	/// in the map for a while so that these can be resynced from gossip in the future.
	///
	/// This method is only available with the `std` feature. See
	/// [`NetworkGraph::remove_stale_channels_and_tracking_with_time`] for `no-std` use.
	pub fn remove_stale_channels_and_tracking(&self) {
		let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
		self.remove_stale_channels_and_tracking_with_time(time);
	}

	/// Removes information about channels that we haven't heard any updates about in some time.
	/// This can be used regularly to prune the network graph of channels that likely no longer
	/// exist.
	///
	/// While there is no formal requirement that nodes regularly re-broadcast their channel
	/// updates every two weeks, the non-normative section of BOLT 7 currently suggests that
	/// pruning occur for updates which are at least two weeks old, which we implement here.
	///
	/// This method will also cause us to stop tracking removed nodes and channels if they have been
	/// in the map for a while so that these can be resynced from gossip in the future.
	///
	/// This function takes the current unix time as an argument. For users with the `std` feature
	/// enabled, [`NetworkGraph::remove_stale_channels_and_tracking`] may be preferable.
	pub fn remove_stale_channels_and_tracking_with_time(&self, current_time_unix: u64) {
		let mut channels = self.channels.write().unwrap();
		// Time out if we haven't received an update in at least 14 days.
		if current_time_unix > u32::max_value() as u64 { return; } // Remove by 2106
		if current_time_unix < STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS { return; }
		let min_time_unix: u32 = (current_time_unix - STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS) as u32;
		// Sadly BTreeMap::retain was only stabilized in 1.53 so we can't switch to it for some
		// time.
		let mut scids_to_remove = Vec::new();
		for (scid, info) in channels.unordered_iter_mut() {
			if info.one_to_two.is_some() && info.one_to_two.as_ref().unwrap().last_update < min_time_unix {
				info.one_to_two = None;
			}
			if info.two_to_one.is_some() && info.two_to_one.as_ref().unwrap().last_update < min_time_unix {
				info.two_to_one = None;
			}
			if info.one_to_two.is_none() || info.two_to_one.is_none() {
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
				self.removed_channels.lock().unwrap().insert(scid, Some(current_time_unix));
			}
		}

		let should_keep_tracking = |time: &mut Option<u64>| {
			if let Some(time) = time {
				current_time_unix.saturating_sub(*time) < REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS
			} else {
				// NOTE: In the case of no-std, we won't have access to the current UNIX time at the time of removal,
				// so we'll just set the removal time here to the current UNIX time on the very next invocation
				// of this function.
				#[cfg(feature = "no-std")]
				{
					let mut tracked_time = Some(current_time_unix);
					core::mem::swap(time, &mut tracked_time);
					return true;
				}
				#[allow(unreachable_code)]
				false
			}};

		self.removed_channels.lock().unwrap().retain(|_, time| should_keep_tracking(time));
		self.removed_nodes.lock().unwrap().retain(|_, time| should_keep_tracking(time));
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel.
	///
	/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
	/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
	/// routing messages from a source using a protocol other than the lightning P2P protocol.
	///
	/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
	/// materially in the future will be rejected.
	pub fn update_channel(&self, msg: &msgs::ChannelUpdate) -> Result<(), LightningError> {
		self.update_channel_intern(&msg.contents, Some(&msg), Some(&msg.signature))
	}

	/// For an already known (from announcement) channel, update info about one of the directions
	/// of the channel without verifying the associated signatures. Because we aren't given the
	/// associated signatures here we cannot relay the channel update to any of our peers.
	///
	/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
	/// materially in the future will be rejected.
	pub fn update_channel_unsigned(&self, msg: &msgs::UnsignedChannelUpdate) -> Result<(), LightningError> {
		self.update_channel_intern(msg, None, None)
	}

	fn update_channel_intern(&self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>, sig: Option<&secp256k1::ecdsa::Signature>) -> Result<(), LightningError> {
		let chan_enabled = msg.flags & (1 << 1) != (1 << 1);

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
			None => {
				core::mem::drop(channels);
				self.pending_checks.check_hold_pending_channel_update(msg, full_msg)?;
				return Err(LightningError{err: "Couldn't find channel for update".to_owned(), action: ErrorAction::IgnoreError});
			},
			Some(channel) => {
				if msg.htlc_maximum_msat > MAX_VALUE_MSAT {
					return Err(LightningError{err:
						"htlc_maximum_msat is larger than maximum possible msats".to_owned(),
						action: ErrorAction::IgnoreError});
				}

				if let Some(capacity_sats) = channel.capacity_sats {
					// It's possible channel capacity is available now, although it wasn't available at announcement (so the field is None).
					// Don't query UTXO set here to reduce DoS risks.
					if capacity_sats > MAX_VALUE_MSAT / 1000 || msg.htlc_maximum_msat > capacity_sats * 1000 {
						return Err(LightningError{err:
							"htlc_maximum_msat is larger than channel capacity or capacity is bogus".to_owned(),
							action: ErrorAction::IgnoreError});
					}
				}
				macro_rules! check_update_latest {
					($target: expr) => {
						if let Some(existing_chan_info) = $target.as_ref() {
							// The timestamp field is somewhat of a misnomer - the BOLTs use it to
							// order updates to ensure you always have the latest one, only
							// suggesting  that it be at least the current time. For
							// channel_updates specifically, the BOLTs discuss the possibility of
							// pruning based on the timestamp field being more than two weeks old,
							// but only in the non-normative section.
							if existing_chan_info.last_update > msg.timestamp {
								return Err(LightningError{err: "Update older than last processed update".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
							} else if existing_chan_info.last_update == msg.timestamp {
								return Err(LightningError{err: "Update had same timestamp as last processed update".to_owned(), action: ErrorAction::IgnoreDuplicateGossip});
							}
						}
					}
				}

				macro_rules! get_new_channel_info {
					() => { {
						let last_update_message = if msg.excess_data.len() <= MAX_EXCESS_BYTES_FOR_RELAY
							{ full_msg.cloned() } else { None };

						let updated_channel_update_info = ChannelUpdateInfo {
							enabled: chan_enabled,
							last_update: msg.timestamp,
							cltv_expiry_delta: msg.cltv_expiry_delta,
							htlc_minimum_msat: msg.htlc_minimum_msat,
							htlc_maximum_msat: msg.htlc_maximum_msat,
							fees: RoutingFees {
								base_msat: msg.fee_base_msat,
								proportional_millionths: msg.fee_proportional_millionths,
							},
							last_update_message
						};
						Some(updated_channel_update_info)
					} }
				}

				let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
				if msg.flags & 1 == 1 {
					check_update_latest!(channel.two_to_one);
					if let Some(sig) = sig {
						secp_verify_sig!(self.secp_ctx, &msg_hash, &sig, &PublicKey::from_slice(channel.node_two.as_slice()).map_err(|_| LightningError{
							err: "Couldn't parse source node pubkey".to_owned(),
							action: ErrorAction::IgnoreAndLog(Level::Debug)
						})?, "channel_update");
					}
					channel.two_to_one = get_new_channel_info!();
				} else {
					check_update_latest!(channel.one_to_two);
					if let Some(sig) = sig {
						secp_verify_sig!(self.secp_ctx, &msg_hash, &sig, &PublicKey::from_slice(channel.node_one.as_slice()).map_err(|_| LightningError{
							err: "Couldn't parse destination node pubkey".to_owned(),
							action: ErrorAction::IgnoreAndLog(Level::Debug)
						})?, "channel_update");
					}
					channel.one_to_two = get_new_channel_info!();
				}
			}
		}

		Ok(())
	}

	fn remove_channel_in_nodes(nodes: &mut IndexedMap<NodeId, NodeInfo>, chan: &ChannelInfo, short_channel_id: u64) {
		macro_rules! remove_from_node {
			($node_id: expr) => {
				if let IndexedMapEntry::Occupied(mut entry) = nodes.entry($node_id) {
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
	/// (C-not exported) because we don't want to return lifetime'd references
	pub fn channels(&self) -> &IndexedMap<u64, ChannelInfo> {
		&*self.channels
	}

	/// Returns information on a channel with the given id.
	pub fn channel(&self, short_channel_id: u64) -> Option<&ChannelInfo> {
		self.channels.get(&short_channel_id)
	}

	#[cfg(c_bindings)] // Non-bindings users should use `channels`
	/// Returns the list of channels in the graph
	pub fn list_channels(&self) -> Vec<u64> {
		self.channels.unordered_keys().map(|c| *c).collect()
	}

	/// Returns all known nodes' public keys along with announced node info.
	///
	/// (C-not exported) because we don't want to return lifetime'd references
	pub fn nodes(&self) -> &IndexedMap<NodeId, NodeInfo> {
		&*self.nodes
	}

	/// Returns information on a node with the given id.
	pub fn node(&self, node_id: &NodeId) -> Option<&NodeInfo> {
		self.nodes.get(node_id)
	}

	#[cfg(c_bindings)] // Non-bindings users should use `nodes`
	/// Returns the list of nodes in the graph
	pub fn list_nodes(&self) -> Vec<NodeId> {
		self.nodes.unordered_keys().map(|n| *n).collect()
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
pub(crate) mod tests {
	use crate::ln::channelmanager;
	use crate::ln::chan_utils::make_funding_redeemscript;
	#[cfg(feature = "std")]
	use crate::ln::features::InitFeatures;
	use crate::routing::gossip::{P2PGossipSync, NetworkGraph, NetworkUpdate, NodeAlias, MAX_EXCESS_BYTES_FOR_RELAY, NodeId, RoutingFees, ChannelUpdateInfo, ChannelInfo, NodeAnnouncementInfo, NodeInfo};
	use crate::routing::utxo::{UtxoLookupError, UtxoResult};
	use crate::ln::msgs::{RoutingMessageHandler, UnsignedNodeAnnouncement, NodeAnnouncement,
		UnsignedChannelAnnouncement, ChannelAnnouncement, UnsignedChannelUpdate, ChannelUpdate,
		ReplyChannelRange, QueryChannelRange, QueryShortChannelIds, MAX_VALUE_MSAT};
	use crate::util::config::UserConfig;
	use crate::util::test_utils;
	use crate::util::ser::{ReadableArgs, Writeable};
	use crate::util::events::{MessageSendEvent, MessageSendEventsProvider};
	use crate::util::scid_utils::scid_from_parts;

	use crate::routing::gossip::REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS;
	use super::STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS;

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Script;
	use bitcoin::blockdata::transaction::TxOut;

	use hex;

	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use bitcoin::secp256k1::{All, Secp256k1};

	use crate::io;
	use bitcoin::secp256k1;
	use crate::prelude::*;
	use crate::sync::Arc;

	fn create_network_graph() -> NetworkGraph<Arc<test_utils::TestLogger>> {
		let logger = Arc::new(test_utils::TestLogger::new());
		NetworkGraph::new(Network::Testnet, logger)
	}

	fn create_gossip_sync(network_graph: &NetworkGraph<Arc<test_utils::TestLogger>>) -> (
		Secp256k1<All>, P2PGossipSync<&NetworkGraph<Arc<test_utils::TestLogger>>,
		Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let gossip_sync = P2PGossipSync::new(network_graph, None, Arc::clone(&logger));
		(secp_ctx, gossip_sync)
	}

	#[test]
	#[cfg(feature = "std")]
	fn request_full_sync_finite_times() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
		let node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()[..]).unwrap());

		assert!(gossip_sync.should_request_full_sync(&node_id));
		assert!(gossip_sync.should_request_full_sync(&node_id));
		assert!(gossip_sync.should_request_full_sync(&node_id));
		assert!(gossip_sync.should_request_full_sync(&node_id));
		assert!(gossip_sync.should_request_full_sync(&node_id));
		assert!(!gossip_sync.should_request_full_sync(&node_id));
	}

	pub(crate) fn get_signed_node_announcement<F: Fn(&mut UnsignedNodeAnnouncement)>(f: F, node_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> NodeAnnouncement {
		let node_id = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_key));
		let mut unsigned_announcement = UnsignedNodeAnnouncement {
			features: channelmanager::provided_node_features(&UserConfig::default()),
			timestamp: 100,
			node_id,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		f(&mut unsigned_announcement);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		NodeAnnouncement {
			signature: secp_ctx.sign_ecdsa(&msghash, node_key),
			contents: unsigned_announcement
		}
	}

	pub(crate) fn get_signed_channel_announcement<F: Fn(&mut UnsignedChannelAnnouncement)>(f: F, node_1_key: &SecretKey, node_2_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> ChannelAnnouncement {
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_key);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_key);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let mut unsigned_announcement = UnsignedChannelAnnouncement {
			features: channelmanager::provided_channel_features(&UserConfig::default()),
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 0,
			node_id_1: NodeId::from_pubkey(&node_id_1),
			node_id_2: NodeId::from_pubkey(&node_id_2),
			bitcoin_key_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_1_btckey)),
			bitcoin_key_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_2_btckey)),
			excess_data: Vec::new(),
		};
		f(&mut unsigned_announcement);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		ChannelAnnouncement {
			node_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_key),
			node_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_key),
			bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_btckey),
			bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_btckey),
			contents: unsigned_announcement,
		}
	}

	pub(crate) fn get_channel_script(secp_ctx: &Secp256k1<secp256k1::All>) -> Script {
		let node_1_btckey = SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = SecretKey::from_slice(&[39; 32]).unwrap();
		make_funding_redeemscript(&PublicKey::from_secret_key(secp_ctx, &node_1_btckey),
			&PublicKey::from_secret_key(secp_ctx, &node_2_btckey)).to_v0_p2wsh()
	}

	pub(crate) fn get_signed_channel_update<F: Fn(&mut UnsignedChannelUpdate)>(f: F, node_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> ChannelUpdate {
		let mut unsigned_channel_update = UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 0,
			timestamp: 100,
			flags: 0,
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1_000_000,
			htlc_maximum_msat: 1_000_000,
			fee_base_msat: 10_000,
			fee_proportional_millionths: 20,
			excess_data: Vec::new()
		};
		f(&mut unsigned_channel_update);
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_channel_update.encode()[..])[..]);
		ChannelUpdate {
			signature: secp_ctx.sign_ecdsa(&msghash, node_key),
			contents: unsigned_channel_update
		}
	}

	#[test]
	fn handling_node_announcements() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let zero_hash = Sha256dHash::hash(&[0; 32]);

		let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_node_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!("No existing channels for node_announcement", e.err)
		};

		{
			// Announce a channel to add a corresponding node.
			let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			match gossip_sync.handle_channel_announcement(&valid_announcement) {
				Ok(res) => assert!(res),
				_ => panic!()
			};
		}

		match gossip_sync.handle_node_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			Err(_) => panic!()
		};

		let fake_msghash = hash_to_message!(&zero_hash);
		match gossip_sync.handle_node_announcement(
			&NodeAnnouncement {
				signature: secp_ctx.sign_ecdsa(&fake_msghash, node_1_privkey),
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
		match gossip_sync.handle_node_announcement(&announcement_with_data) {
			Ok(res) => assert!(!res),
			Err(_) => panic!()
		};

		// Even though previous announcement was not relayed further, we still accepted it,
		// so we now won't accept announcements before the previous one.
		let outdated_announcement = get_signed_node_announcement(|unsigned_announcement| {
			unsigned_announcement.timestamp += 1000 - 10;
		}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_node_announcement(&outdated_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Update older than last processed update")
		};
	}

	#[test]
	fn handling_channel_announcements() {
		let secp_ctx = Secp256k1::new();
		let logger = test_utils::TestLogger::new();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let good_script = get_channel_script(&secp_ctx);
		let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);

		// Test if the UTXO lookups were not supported
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let mut gossip_sync = P2PGossipSync::new(&network_graph, None, &logger);
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
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
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Already have non-chain-validated channel")
		};

		// Test if an associated transaction were not on-chain (or not confirmed).
		let chain_source = test_utils::TestChainSource::new(Network::Testnet);
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Err(UtxoLookupError::UnknownTx));
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		gossip_sync = P2PGossipSync::new(&network_graph, Some(&chain_source), &logger);

		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 1;
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announced without corresponding UTXO entry")
		};

		// Now test if the transaction is found in the UTXO set and the script is correct.
		*chain_source.utxo_ret.lock().unwrap() =
			UtxoResult::Sync(Ok(TxOut { value: 0, script_pubkey: good_script.clone() }));
		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 2;
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		{
			match network_graph.read_only().channels().get(&valid_announcement.contents.short_channel_id) {
				None => panic!(),
				Some(_) => ()
			};
		}

		// If we receive announcement for the same channel, once we've validated it against the
		// chain, we simply ignore all new (duplicate) announcements.
		*chain_source.utxo_ret.lock().unwrap() =
			UtxoResult::Sync(Ok(TxOut { value: 0, script_pubkey: good_script }));
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Already have chain-validated channel")
		};

		#[cfg(feature = "std")]
		{
			use std::time::{SystemTime, UNIX_EPOCH};

			let tracking_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			// Mark a node as permanently failed so it's tracked as removed.
			gossip_sync.network_graph().node_failed_permanent(&PublicKey::from_secret_key(&secp_ctx, node_1_privkey));

			// Return error and ignore valid channel announcement if one of the nodes has been tracked as removed.
			let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
				unsigned_announcement.short_channel_id += 3;
			}, node_1_privkey, node_2_privkey, &secp_ctx);
			match gossip_sync.handle_channel_announcement(&valid_announcement) {
				Ok(_) => panic!(),
				Err(e) => assert_eq!(e.err, "Channel with SCID 3 or one of its nodes was removed from our network graph recently")
			}

			gossip_sync.network_graph().remove_stale_channels_and_tracking_with_time(tracking_time + REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS);

			// The above channel announcement should be handled as per normal now.
			match gossip_sync.handle_channel_announcement(&valid_announcement) {
				Ok(res) => assert!(res),
				_ => panic!()
			}
		}

		// Don't relay valid channels with excess data
		let valid_announcement = get_signed_channel_announcement(|unsigned_announcement| {
			unsigned_announcement.short_channel_id += 4;
			unsigned_announcement.excess_data.resize(MAX_EXCESS_BYTES_FOR_RELAY + 1, 0);
		}, node_1_privkey, node_2_privkey, &secp_ctx);
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};

		let mut invalid_sig_announcement = valid_announcement.clone();
		invalid_sig_announcement.contents.excess_data = Vec::new();
		match gossip_sync.handle_channel_announcement(&invalid_sig_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature on channel_announcement message")
		};

		let channel_to_itself_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_announcement(&channel_to_itself_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announcement node had a channel with itself")
		};
	}

	#[test]
	fn handling_channel_update() {
		let secp_ctx = Secp256k1::new();
		let logger = test_utils::TestLogger::new();
		let chain_source = test_utils::TestChainSource::new(Network::Testnet);
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let gossip_sync = P2PGossipSync::new(&network_graph, Some(&chain_source), &logger);

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let amount_sats = 1000_000;
		let short_channel_id;

		{
			// Announce a channel we will update
			let good_script = get_channel_script(&secp_ctx);
			*chain_source.utxo_ret.lock().unwrap() =
				UtxoResult::Sync(Ok(TxOut { value: amount_sats, script_pubkey: good_script.clone() }));

			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			short_channel_id = valid_channel_announcement.contents.short_channel_id;
			match gossip_sync.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

		}

		let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			_ => panic!(),
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
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(!res),
			_ => panic!()
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 110;
			unsigned_channel_update.short_channel_id += 1;
		}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Couldn't find channel for update")
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.htlc_maximum_msat = MAX_VALUE_MSAT + 1;
			unsigned_channel_update.timestamp += 110;
		}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than maximum possible msats")
		};

		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.htlc_maximum_msat = amount_sats * 1000 + 1;
			unsigned_channel_update.timestamp += 110;
		}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "htlc_maximum_msat is larger than channel capacity or capacity is bogus")
		};

		// Even though previous update was not relayed further, we still accepted it,
		// so we now won't accept update before the previous one.
		let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 100;
		}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Update had same timestamp as last processed update")
		};

		let mut invalid_sig_channel_update = get_signed_channel_update(|unsigned_channel_update| {
			unsigned_channel_update.timestamp += 500;
		}, node_1_privkey, &secp_ctx);
		let zero_hash = Sha256dHash::hash(&[0; 32]);
		let fake_msghash = hash_to_message!(&zero_hash);
		invalid_sig_channel_update.signature = secp_ctx.sign_ecdsa(&fake_msghash, node_1_privkey);
		match gossip_sync.handle_channel_update(&invalid_sig_channel_update) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Invalid signature on channel_update message")
		};
	}

	#[test]
	fn handling_network_update() {
		let logger = test_utils::TestLogger::new();
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let secp_ctx = Secp256k1::new();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_2_id = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);

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
			assert!(network_graph.update_channel_from_announcement(&valid_channel_announcement, &chain_source).is_ok());
			assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());

			let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_none());

			network_graph.handle_network_update(&NetworkUpdate::ChannelUpdateMessage {
				msg: valid_channel_update,
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

			network_graph.handle_network_update(&NetworkUpdate::ChannelFailure {
				short_channel_id,
				is_permanent: false,
			});

			match network_graph.read_only().channels().get(&short_channel_id) {
				None => panic!(),
				Some(channel_info) => {
					assert!(!channel_info.one_to_two.as_ref().unwrap().enabled);
				}
			};
		}

		// Permanent closing deletes a channel
		network_graph.handle_network_update(&NetworkUpdate::ChannelFailure {
			short_channel_id,
			is_permanent: true,
		});

		assert_eq!(network_graph.read_only().channels().len(), 0);
		// Nodes are also deleted because there are no associated channels anymore
		assert_eq!(network_graph.read_only().nodes().len(), 0);

		{
			// Get a new network graph since we don't want to track removed nodes in this test with "std"
			let network_graph = NetworkGraph::new(Network::Testnet, &logger);

			// Announce a channel to test permanent node failure
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			let short_channel_id = valid_channel_announcement.contents.short_channel_id;
			let chain_source: Option<&test_utils::TestChainSource> = None;
			assert!(network_graph.update_channel_from_announcement(&valid_channel_announcement, &chain_source).is_ok());
			assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());

			// Non-permanent node failure does not delete any nodes or channels
			network_graph.handle_network_update(&NetworkUpdate::NodeFailure {
				node_id: node_2_id,
				is_permanent: false,
			});

			assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());
			assert!(network_graph.read_only().nodes().get(&NodeId::from_pubkey(&node_2_id)).is_some());

			// Permanent node failure deletes node and its channels
			network_graph.handle_network_update(&NetworkUpdate::NodeFailure {
				node_id: node_2_id,
				is_permanent: true,
			});

			assert_eq!(network_graph.read_only().nodes().len(), 0);
			// Channels are also deleted because the associated node has been deleted
			assert_eq!(network_graph.read_only().channels().len(), 0);
		}
	}

	#[test]
	fn test_channel_timeouts() {
		// Test the removal of channels with `remove_stale_channels_and_tracking`.
		let logger = test_utils::TestLogger::new();
		let chain_source = test_utils::TestChainSource::new(Network::Testnet);
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let gossip_sync = P2PGossipSync::new(&network_graph, Some(&chain_source), &logger);
		let secp_ctx = Secp256k1::new();

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		let short_channel_id = valid_channel_announcement.contents.short_channel_id;
		let chain_source: Option<&test_utils::TestChainSource> = None;
		assert!(network_graph.update_channel_from_announcement(&valid_channel_announcement, &chain_source).is_ok());
		assert!(network_graph.read_only().channels().get(&short_channel_id).is_some());

		// Submit two channel updates for each channel direction (update.flags bit).
		let valid_channel_update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
		assert!(gossip_sync.handle_channel_update(&valid_channel_update).is_ok());
		assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_some());

		let valid_channel_update_2 = get_signed_channel_update(|update| {update.flags |=1;}, node_2_privkey, &secp_ctx);
		gossip_sync.handle_channel_update(&valid_channel_update_2).unwrap();
		assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().two_to_one.is_some());

		network_graph.remove_stale_channels_and_tracking_with_time(100 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
		assert_eq!(network_graph.read_only().channels().len(), 1);
		assert_eq!(network_graph.read_only().nodes().len(), 2);

		network_graph.remove_stale_channels_and_tracking_with_time(101 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
		#[cfg(not(feature = "std"))] {
			// Make sure removed channels are tracked.
			assert_eq!(network_graph.removed_channels.lock().unwrap().len(), 1);
		}
		network_graph.remove_stale_channels_and_tracking_with_time(101 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS +
			REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS);

		#[cfg(feature = "std")]
		{
			// In std mode, a further check is performed before fully removing the channel -
			// the channel_announcement must have been received at least two weeks ago. We
			// fudge that here by indicating the time has jumped two weeks.
			assert_eq!(network_graph.read_only().channels().len(), 1);
			assert_eq!(network_graph.read_only().nodes().len(), 2);

			// Note that the directional channel information will have been removed already..
			// We want to check that this will work even if *one* of the channel updates is recent,
			// so we should add it with a recent timestamp.
			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_none());
			use std::time::{SystemTime, UNIX_EPOCH};
			let announcement_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			let valid_channel_update = get_signed_channel_update(|unsigned_channel_update| {
				unsigned_channel_update.timestamp = (announcement_time + 1 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS) as u32;
			}, node_1_privkey, &secp_ctx);
			assert!(gossip_sync.handle_channel_update(&valid_channel_update).is_ok());
			assert!(network_graph.read_only().channels().get(&short_channel_id).unwrap().one_to_two.is_some());
			network_graph.remove_stale_channels_and_tracking_with_time(announcement_time + 1 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS);
			// Make sure removed channels are tracked.
			assert_eq!(network_graph.removed_channels.lock().unwrap().len(), 1);
			// Provide a later time so that sufficient time has passed
			network_graph.remove_stale_channels_and_tracking_with_time(announcement_time + 1 + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS +
				REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS);
		}

		assert_eq!(network_graph.read_only().channels().len(), 0);
		assert_eq!(network_graph.read_only().nodes().len(), 0);
		assert!(network_graph.removed_channels.lock().unwrap().is_empty());

		#[cfg(feature = "std")]
		{
			use std::time::{SystemTime, UNIX_EPOCH};

			let tracking_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();

			// Clear tracked nodes and channels for clean slate
			network_graph.removed_channels.lock().unwrap().clear();
			network_graph.removed_nodes.lock().unwrap().clear();

			// Add a channel and nodes from channel announcement. So our network graph will
			// now only consist of two nodes and one channel between them.
			assert!(network_graph.update_channel_from_announcement(
				&valid_channel_announcement, &chain_source).is_ok());

			// Mark the channel as permanently failed. This will also remove the two nodes
			// and all of the entries will be tracked as removed.
			network_graph.channel_failed_with_time(short_channel_id, true, Some(tracking_time));

			// Should not remove from tracking if insufficient time has passed
			network_graph.remove_stale_channels_and_tracking_with_time(
				tracking_time + REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS - 1);
			assert_eq!(network_graph.removed_channels.lock().unwrap().len(), 1, "Removed channel count ≠ 1 with tracking_time {}", tracking_time);

			// Provide a later time so that sufficient time has passed
			network_graph.remove_stale_channels_and_tracking_with_time(
				tracking_time + REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS);
			assert!(network_graph.removed_channels.lock().unwrap().is_empty(), "Unexpectedly removed channels with tracking_time {}", tracking_time);
			assert!(network_graph.removed_nodes.lock().unwrap().is_empty(), "Unexpectedly removed nodes with tracking_time {}", tracking_time);
		}

		#[cfg(not(feature = "std"))]
		{
			// When we don't have access to the system clock, the time we started tracking removal will only
			// be that provided by the first call to `remove_stale_channels_and_tracking_with_time`. Hence,
			// only if sufficient time has passed after that first call, will the next call remove it from
			// tracking.
			let removal_time = 1664619654;

			// Clear removed nodes and channels for clean slate
			network_graph.removed_channels.lock().unwrap().clear();
			network_graph.removed_nodes.lock().unwrap().clear();

			// Add a channel and nodes from channel announcement. So our network graph will
			// now only consist of two nodes and one channel between them.
			assert!(network_graph.update_channel_from_announcement(
				&valid_channel_announcement, &chain_source).is_ok());

			// Mark the channel as permanently failed. This will also remove the two nodes
			// and all of the entries will be tracked as removed.
			network_graph.channel_failed(short_channel_id, true);

			// The first time we call the following, the channel will have a removal time assigned.
			network_graph.remove_stale_channels_and_tracking_with_time(removal_time);
			assert_eq!(network_graph.removed_channels.lock().unwrap().len(), 1);

			// Provide a later time so that sufficient time has passed
			network_graph.remove_stale_channels_and_tracking_with_time(
				removal_time + REMOVED_ENTRIES_TRACKING_AGE_LIMIT_SECS);
			assert!(network_graph.removed_channels.lock().unwrap().is_empty());
			assert!(network_graph.removed_nodes.lock().unwrap().is_empty());
		}
	}

	#[test]
	fn getting_next_channel_announcements() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		// Channels were not announced yet.
		let channels_with_announcements = gossip_sync.get_next_channel_announcement(0);
		assert!(channels_with_announcements.is_none());

		let short_channel_id;
		{
			// Announce a channel we will update
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			short_channel_id = valid_channel_announcement.contents.short_channel_id;
			match gossip_sync.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Contains initial channel announcement now.
		let channels_with_announcements = gossip_sync.get_next_channel_announcement(short_channel_id);
		if let Some(channel_announcements) = channels_with_announcements {
			let (_, ref update_1, ref update_2) = channel_announcements;
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
			match gossip_sync.handle_channel_update(&valid_channel_update) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Now contains an initial announcement and an update.
		let channels_with_announcements = gossip_sync.get_next_channel_announcement(short_channel_id);
		if let Some(channel_announcements) = channels_with_announcements {
			let (_, ref update_1, ref update_2) = channel_announcements;
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
			match gossip_sync.handle_channel_update(&valid_channel_update) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Test that announcements with excess data won't be returned
		let channels_with_announcements = gossip_sync.get_next_channel_announcement(short_channel_id);
		if let Some(channel_announcements) = channels_with_announcements {
			let (_, ref update_1, ref update_2) = channel_announcements;
			assert_eq!(update_1, &None);
			assert_eq!(update_2, &None);
		} else {
			panic!();
		}

		// Further starting point have no channels after it
		let channels_with_announcements = gossip_sync.get_next_channel_announcement(short_channel_id + 1000);
		assert!(channels_with_announcements.is_none());
	}

	#[test]
	fn getting_next_node_announcements() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_1_privkey));

		// No nodes yet.
		let next_announcements = gossip_sync.get_next_node_announcement(None);
		assert!(next_announcements.is_none());

		{
			// Announce a channel to add 2 nodes
			let valid_channel_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			match gossip_sync.handle_channel_announcement(&valid_channel_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		// Nodes were never announced
		let next_announcements = gossip_sync.get_next_node_announcement(None);
		assert!(next_announcements.is_none());

		{
			let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
			match gossip_sync.handle_node_announcement(&valid_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};

			let valid_announcement = get_signed_node_announcement(|_| {}, node_2_privkey, &secp_ctx);
			match gossip_sync.handle_node_announcement(&valid_announcement) {
				Ok(_) => (),
				Err(_) => panic!()
			};
		}

		let next_announcements = gossip_sync.get_next_node_announcement(None);
		assert!(next_announcements.is_some());

		// Skip the first node.
		let next_announcements = gossip_sync.get_next_node_announcement(Some(&node_id_1));
		assert!(next_announcements.is_some());

		{
			// Later announcement which should not be relayed (excess data) prevent us from sharing a node
			let valid_announcement = get_signed_node_announcement(|unsigned_announcement| {
				unsigned_announcement.timestamp += 10;
				unsigned_announcement.excess_data = [1; MAX_EXCESS_BYTES_FOR_RELAY + 1].to_vec();
			}, node_2_privkey, &secp_ctx);
			match gossip_sync.handle_node_announcement(&valid_announcement) {
				Ok(res) => assert!(!res),
				Err(_) => panic!()
			};
		}

		let next_announcements = gossip_sync.get_next_node_announcement(Some(&node_id_1));
		assert!(next_announcements.is_none());
	}

	#[test]
	fn network_graph_serialization() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		// Announce a channel to add a corresponding node.
		let valid_announcement = get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};

		let valid_announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
		match gossip_sync.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};

		let mut w = test_utils::TestVecWriter(Vec::new());
		assert!(!network_graph.read_only().nodes().is_empty());
		assert!(!network_graph.read_only().channels().is_empty());
		network_graph.write(&mut w).unwrap();

		let logger = Arc::new(test_utils::TestLogger::new());
		assert!(<NetworkGraph<_>>::read(&mut io::Cursor::new(&w.0), logger).unwrap() == network_graph);
	}

	#[test]
	fn network_graph_tlv_serialization() {
		let network_graph = create_network_graph();
		network_graph.set_last_rapid_gossip_sync_timestamp(42);

		let mut w = test_utils::TestVecWriter(Vec::new());
		network_graph.write(&mut w).unwrap();

		let logger = Arc::new(test_utils::TestLogger::new());
		let reassembled_network_graph: NetworkGraph<_> = ReadableArgs::read(&mut io::Cursor::new(&w.0), logger).unwrap();
		assert!(reassembled_network_graph == network_graph);
		assert_eq!(reassembled_network_graph.get_last_rapid_gossip_sync_timestamp().unwrap(), 42);
	}

	#[test]
	#[cfg(feature = "std")]
	fn calling_sync_routing_table() {
		use std::time::{SystemTime, UNIX_EPOCH};
		use crate::ln::msgs::Init;

		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
		let node_privkey_1 = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_privkey_1);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		// It should ignore if gossip_queries feature is not enabled
		{
			let init_msg = Init { features: InitFeatures::empty(), remote_network_address: None };
			gossip_sync.peer_connected(&node_id_1, &init_msg, true).unwrap();
			let events = gossip_sync.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 0);
		}

		// It should send a gossip_timestamp_filter with the correct information
		{
			let mut features = InitFeatures::empty();
			features.set_gossip_queries_optional();
			let init_msg = Init { features, remote_network_address: None };
			gossip_sync.peer_connected(&node_id_1, &init_msg, true).unwrap();
			let events = gossip_sync.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				MessageSendEvent::SendGossipTimestampFilter{ node_id, msg } => {
					assert_eq!(node_id, &node_id_1);
					assert_eq!(msg.chain_hash, chain_hash);
					let expected_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
					assert!((msg.first_timestamp as u64) >= expected_timestamp - 60*60*24*7*2);
					assert!((msg.first_timestamp as u64) < expected_timestamp - 60*60*24*7*2 + 10);
					assert_eq!(msg.timestamp_range, u32::max_value());
				},
				_ => panic!("Expected MessageSendEvent::SendChannelRangeQuery")
			};
		}
	}

	#[test]
	fn handling_query_channel_range() {
		let network_graph = create_network_graph();
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);

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
			match gossip_sync.handle_channel_announcement(&valid_announcement) {
				Ok(_) => (),
				_ => panic!()
			};
		}

		// Error when number_of_blocks=0
		do_handling_query_channel_range(
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
			&gossip_sync,
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
		gossip_sync: &P2PGossipSync<&NetworkGraph<Arc<test_utils::TestLogger>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		test_node_id: &PublicKey,
		msg: QueryChannelRange,
		expected_ok: bool,
		expected_replies: Vec<ReplyChannelRange>
	) {
		let mut max_firstblocknum = msg.first_blocknum.saturating_sub(1);
		let mut c_lightning_0_9_prev_end_blocknum = max_firstblocknum;
		let query_end_blocknum = msg.end_blocknum();
		let result = gossip_sync.handle_query_channel_range(test_node_id, msg);

		if expected_ok {
			assert!(result.is_ok());
		} else {
			assert!(result.is_err());
		}

		let events = gossip_sync.get_and_clear_pending_msg_events();
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
		let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
		let node_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);

		let chain_hash = genesis_block(Network::Testnet).header.block_hash();

		let result = gossip_sync.handle_query_short_channel_ids(&node_id, QueryShortChannelIds {
			chain_hash,
			short_channel_ids: vec![0x0003e8_000000_0000],
		});
		assert!(result.is_err());
	}

	#[test]
	fn displays_node_alias() {
		let format_str_alias = |alias: &str| {
			let mut bytes = [0u8; 32];
			bytes[..alias.as_bytes().len()].copy_from_slice(alias.as_bytes());
			format!("{}", NodeAlias(bytes))
		};

		assert_eq!(format_str_alias("I\u{1F496}LDK! \u{26A1}"), "I\u{1F496}LDK! \u{26A1}");
		assert_eq!(format_str_alias("I\u{1F496}LDK!\0\u{26A1}"), "I\u{1F496}LDK!");
		assert_eq!(format_str_alias("I\u{1F496}LDK!\t\u{26A1}"), "I\u{1F496}LDK!\u{FFFD}\u{26A1}");

		let format_bytes_alias = |alias: &[u8]| {
			let mut bytes = [0u8; 32];
			bytes[..alias.len()].copy_from_slice(alias);
			format!("{}", NodeAlias(bytes))
		};

		assert_eq!(format_bytes_alias(b"\xFFI <heart> LDK!"), "\u{FFFD}I <heart> LDK!");
		assert_eq!(format_bytes_alias(b"\xFFI <heart>\0LDK!"), "\u{FFFD}I <heart>");
		assert_eq!(format_bytes_alias(b"\xFFI <heart>\tLDK!"), "\u{FFFD}I <heart>\u{FFFD}LDK!");
	}

	#[test]
	fn channel_info_is_readable() {
		let chanmon_cfgs = crate::ln::functional_test_utils::create_chanmon_cfgs(2);
		let node_cfgs = crate::ln::functional_test_utils::create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = crate::ln::functional_test_utils::create_node_chanmgrs(2, &node_cfgs, &[None, None, None, None]);
		let nodes = crate::ln::functional_test_utils::create_network(2, &node_cfgs, &node_chanmgrs);
		let config = crate::ln::functional_test_utils::test_default_channel_config();

		// 1. Test encoding/decoding of ChannelUpdateInfo
		let chan_update_info = ChannelUpdateInfo {
			last_update: 23,
			enabled: true,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1234,
			htlc_maximum_msat: 5678,
			fees: RoutingFees { base_msat: 9, proportional_millionths: 10 },
			last_update_message: None,
		};

		let mut encoded_chan_update_info: Vec<u8> = Vec::new();
		assert!(chan_update_info.write(&mut encoded_chan_update_info).is_ok());

		// First make sure we can read ChannelUpdateInfos we just wrote
		let read_chan_update_info: ChannelUpdateInfo = crate::util::ser::Readable::read(&mut encoded_chan_update_info.as_slice()).unwrap();
		assert_eq!(chan_update_info, read_chan_update_info);

		// Check the serialization hasn't changed.
		let legacy_chan_update_info_with_some: Vec<u8> = hex::decode("340004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c0100").unwrap();
		assert_eq!(encoded_chan_update_info, legacy_chan_update_info_with_some);

		// Check we fail if htlc_maximum_msat is not present in either the ChannelUpdateInfo itself
		// or the ChannelUpdate enclosed with `last_update_message`.
		let legacy_chan_update_info_with_some_and_fail_update: Vec<u8> = hex::decode("b40004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c8181d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00083a840000034d013413a70000009000000000000f42400000271000000014").unwrap();
		let read_chan_update_info_res: Result<ChannelUpdateInfo, crate::ln::msgs::DecodeError> = crate::util::ser::Readable::read(&mut legacy_chan_update_info_with_some_and_fail_update.as_slice());
		assert!(read_chan_update_info_res.is_err());

		let legacy_chan_update_info_with_none: Vec<u8> = hex::decode("2c0004000000170201010402002a060800000000000004d20801000a0d0c00040000000902040000000a0c0100").unwrap();
		let read_chan_update_info_res: Result<ChannelUpdateInfo, crate::ln::msgs::DecodeError> = crate::util::ser::Readable::read(&mut legacy_chan_update_info_with_none.as_slice());
		assert!(read_chan_update_info_res.is_err());

		// 2. Test encoding/decoding of ChannelInfo
		// Check we can encode/decode ChannelInfo without ChannelUpdateInfo fields present.
		let chan_info_none_updates = ChannelInfo {
			features: channelmanager::provided_channel_features(&config),
			node_one: NodeId::from_pubkey(&nodes[0].node.get_our_node_id()),
			one_to_two: None,
			node_two: NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			two_to_one: None,
			capacity_sats: None,
			announcement_message: None,
			announcement_received_time: 87654,
		};

		let mut encoded_chan_info: Vec<u8> = Vec::new();
		assert!(chan_info_none_updates.write(&mut encoded_chan_info).is_ok());

		let read_chan_info: ChannelInfo = crate::util::ser::Readable::read(&mut encoded_chan_info.as_slice()).unwrap();
		assert_eq!(chan_info_none_updates, read_chan_info);

		// Check we can encode/decode ChannelInfo with ChannelUpdateInfo fields present.
		let chan_info_some_updates = ChannelInfo {
			features: channelmanager::provided_channel_features(&config),
			node_one: NodeId::from_pubkey(&nodes[0].node.get_our_node_id()),
			one_to_two: Some(chan_update_info.clone()),
			node_two: NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			two_to_one: Some(chan_update_info.clone()),
			capacity_sats: None,
			announcement_message: None,
			announcement_received_time: 87654,
		};

		let mut encoded_chan_info: Vec<u8> = Vec::new();
		assert!(chan_info_some_updates.write(&mut encoded_chan_info).is_ok());

		let read_chan_info: ChannelInfo = crate::util::ser::Readable::read(&mut encoded_chan_info.as_slice()).unwrap();
		assert_eq!(chan_info_some_updates, read_chan_info);

		// Check the serialization hasn't changed.
		let legacy_chan_info_with_some: Vec<u8> = hex::decode("ca00020000010800000000000156660221027f921585f2ac0c7c70e36110adecfd8fd14b8a99bfb3d000a283fcac358fce88043636340004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c010006210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c23083636340004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c01000a01000c0100").unwrap();
		assert_eq!(encoded_chan_info, legacy_chan_info_with_some);

		// Check we can decode legacy ChannelInfo, even if the `two_to_one` / `one_to_two` /
		// `last_update_message` fields fail to decode due to missing htlc_maximum_msat.
		let legacy_chan_info_with_some_and_fail_update = hex::decode("fd01ca00020000010800000000000156660221027f921585f2ac0c7c70e36110adecfd8fd14b8a99bfb3d000a283fcac358fce8804b6b6b40004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c8181d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00083a840000034d013413a70000009000000000000f4240000027100000001406210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c2308b6b6b40004000000170201010402002a060800000000000004d2080909000000000000162e0a0d0c00040000000902040000000a0c8181d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00083a840000034d013413a70000009000000000000f424000002710000000140a01000c0100").unwrap();
		let read_chan_info: ChannelInfo = crate::util::ser::Readable::read(&mut legacy_chan_info_with_some_and_fail_update.as_slice()).unwrap();
		assert_eq!(read_chan_info.announcement_received_time, 87654);
		assert_eq!(read_chan_info.one_to_two, None);
		assert_eq!(read_chan_info.two_to_one, None);

		let legacy_chan_info_with_none: Vec<u8> = hex::decode("ba00020000010800000000000156660221027f921585f2ac0c7c70e36110adecfd8fd14b8a99bfb3d000a283fcac358fce88042e2e2c0004000000170201010402002a060800000000000004d20801000a0d0c00040000000902040000000a0c010006210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c23082e2e2c0004000000170201010402002a060800000000000004d20801000a0d0c00040000000902040000000a0c01000a01000c0100").unwrap();
		let read_chan_info: ChannelInfo = crate::util::ser::Readable::read(&mut legacy_chan_info_with_none.as_slice()).unwrap();
		assert_eq!(read_chan_info.announcement_received_time, 87654);
		assert_eq!(read_chan_info.one_to_two, None);
		assert_eq!(read_chan_info.two_to_one, None);
	}

	#[test]
	fn node_info_is_readable() {
		use std::convert::TryFrom;

		// 1. Check we can read a valid NodeAnnouncementInfo and fail on an invalid one
		let valid_netaddr = crate::ln::msgs::NetAddress::Hostname { hostname: crate::util::ser::Hostname::try_from("A".to_string()).unwrap(), port: 1234 };
		let valid_node_ann_info = NodeAnnouncementInfo {
			features: channelmanager::provided_node_features(&UserConfig::default()),
			last_update: 0,
			rgb: [0u8; 3],
			alias: NodeAlias([0u8; 32]),
			addresses: vec![valid_netaddr],
			announcement_message: None,
		};

		let mut encoded_valid_node_ann_info = Vec::new();
		assert!(valid_node_ann_info.write(&mut encoded_valid_node_ann_info).is_ok());
		let read_valid_node_ann_info: NodeAnnouncementInfo = crate::util::ser::Readable::read(&mut encoded_valid_node_ann_info.as_slice()).unwrap();
		assert_eq!(read_valid_node_ann_info, valid_node_ann_info);

		let encoded_invalid_node_ann_info = hex::decode("3f0009000788a000080a51a20204000000000403000000062000000000000000000000000000000000000000000000000000000000000000000a0505014004d2").unwrap();
		let read_invalid_node_ann_info_res: Result<NodeAnnouncementInfo, crate::ln::msgs::DecodeError> = crate::util::ser::Readable::read(&mut encoded_invalid_node_ann_info.as_slice());
		assert!(read_invalid_node_ann_info_res.is_err());

		// 2. Check we can read a NodeInfo anyways, but set the NodeAnnouncementInfo to None if invalid
		let valid_node_info = NodeInfo {
			channels: Vec::new(),
			announcement_info: Some(valid_node_ann_info),
		};

		let mut encoded_valid_node_info = Vec::new();
		assert!(valid_node_info.write(&mut encoded_valid_node_info).is_ok());
		let read_valid_node_info: NodeInfo = crate::util::ser::Readable::read(&mut encoded_valid_node_info.as_slice()).unwrap();
		assert_eq!(read_valid_node_info, valid_node_info);

		let encoded_invalid_node_info_hex = hex::decode("4402403f0009000788a000080a51a20204000000000403000000062000000000000000000000000000000000000000000000000000000000000000000a0505014004d20400").unwrap();
		let read_invalid_node_info: NodeInfo = crate::util::ser::Readable::read(&mut encoded_invalid_node_info_hex.as_slice()).unwrap();
		assert_eq!(read_invalid_node_info.announcement_info, None);
	}
}

#[cfg(all(test, feature = "_bench_unstable"))]
mod benches {
	use super::*;

	use test::Bencher;
	use std::io::Read;

	#[bench]
	fn read_network_graph(bench: &mut Bencher) {
		let logger = crate::util::test_utils::TestLogger::new();
		let mut d = crate::routing::router::bench_utils::get_route_file().unwrap();
		let mut v = Vec::new();
		d.read_to_end(&mut v).unwrap();
		bench.iter(|| {
			let _ = NetworkGraph::read(&mut std::io::Cursor::new(&v), &logger).unwrap();
		});
	}

	#[bench]
	fn write_network_graph(bench: &mut Bencher) {
		let logger = crate::util::test_utils::TestLogger::new();
		let mut d = crate::routing::router::bench_utils::get_route_file().unwrap();
		let net_graph = NetworkGraph::read(&mut d, &logger).unwrap();
		bench.iter(|| {
			let _ = net_graph.encode();
		});
	}
}
