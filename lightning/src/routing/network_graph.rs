//! The top-level network map tracking logic lives here.

use bitcoin::secp256k1::key::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;

use chain::chaininterface::{ChainError, ChainWatchInterface};
use ln::features::{ChannelFeatures, NodeFeatures};
use ln::msgs::{DecodeError,ErrorAction,LightningError,RoutingMessageHandler,NetAddress};
use ln::msgs;
use routing::router::RouteHop;
use util::ser::{Writeable, Readable, Writer};
use util::logger::Logger;

use std::cmp;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry as BtreeEntry;
use std;
use std::ops::Deref;

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
pub struct NetGraphMsgHandler<C: Deref, L: Deref> where C::Target: ChainWatchInterface, L::Target: Logger {
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	/// Representation of the payment channel network
	pub network_graph: RwLock<NetworkGraph>,
	chain_monitor: C,
	full_syncs_requested: AtomicUsize,
	logger: L,
}

impl<C: Deref, L: Deref> NetGraphMsgHandler<C, L> where C::Target: ChainWatchInterface, L::Target: Logger {
	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming a fresh network graph.
	/// Chain monitor is used to make sure announced channels exist on-chain,
	/// channel data is correct, and that the announcement is signed with
	/// channel owners' keys.
	pub fn new(chain_monitor: C, logger: L) -> Self {
		NetGraphMsgHandler {
			secp_ctx: Secp256k1::verification_only(),
			network_graph: RwLock::new(NetworkGraph {
				channels: BTreeMap::new(),
				nodes: BTreeMap::new(),
			}),
			full_syncs_requested: AtomicUsize::new(0),
			chain_monitor,
			logger,
		}
	}

	/// Creates a new tracker of the actual state of the network of channels and nodes,
	/// assuming an existing Network Graph.
	pub fn from_net_graph(chain_monitor: C, logger: L, network_graph: RwLock<NetworkGraph>) -> Self {
		NetGraphMsgHandler {
			secp_ctx: Secp256k1::verification_only(),
			network_graph,
			full_syncs_requested: AtomicUsize::new(0),
			chain_monitor,
			logger,
		}
	}
}


macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr ) => {
		match $secp_ctx.verify($msg, $sig, $pubkey) {
			Ok(_) => {},
			Err(_) => return Err(LightningError{err: "Invalid signature from remote node", action: ErrorAction::IgnoreError}),
		}
	};
}

impl<C: Deref + Sync + Send, L: Deref + Sync + Send> RoutingMessageHandler for NetGraphMsgHandler<C, L> where C::Target: ChainWatchInterface, L::Target: Logger {
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		self.network_graph.write().unwrap().update_node_from_announcement(msg, Some(&self.secp_ctx))
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		if msg.contents.node_id_1 == msg.contents.node_id_2 || msg.contents.bitcoin_key_1 == msg.contents.bitcoin_key_2 {
			return Err(LightningError{err: "Channel announcement node had a channel with itself", action: ErrorAction::IgnoreError});
		}

		let checked_utxo = match self.chain_monitor.get_chain_utxo(msg.contents.chain_hash, msg.contents.short_channel_id) {
			Ok((script_pubkey, _value)) => {
				let expected_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
				                                    .push_slice(&msg.contents.bitcoin_key_1.serialize())
				                                    .push_slice(&msg.contents.bitcoin_key_2.serialize())
				                                    .push_opcode(opcodes::all::OP_PUSHNUM_2)
				                                    .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();
				if script_pubkey != expected_script {
					return Err(LightningError{err: "Channel announcement keys didn't match on-chain script", action: ErrorAction::IgnoreError});
				}
				//TODO: Check if value is worth storing, use it to inform routing, and compare it
				//to the new HTLC max field in channel_update
				true
			},
			Err(ChainError::NotSupported) => {
				// Tentatively accept, potentially exposing us to DoS attacks
				false
			},
			Err(ChainError::NotWatched) => {
				return Err(LightningError{err: "Channel announced on an unknown chain", action: ErrorAction::IgnoreError});
			},
			Err(ChainError::UnknownTx) => {
				return Err(LightningError{err: "Channel announced without corresponding UTXO entry", action: ErrorAction::IgnoreError});
			},
		};
		let result = self.network_graph.write().unwrap().update_channel_from_announcement(msg, checked_utxo, Some(&self.secp_ctx));
		log_trace!(self.logger, "Added channel_announcement for {}{}", msg.contents.short_channel_id, if !msg.contents.excess_data.is_empty() { " with excess uninterpreted data!" } else { "" });
		result
	}

	fn handle_htlc_fail_channel_update(&self, update: &msgs::HTLCFailChannelUpdate) {
		match update {
			&msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg } => {
				let _ = self.network_graph.write().unwrap().update_channel(msg, Some(&self.secp_ctx));
			},
			&msgs::HTLCFailChannelUpdate::ChannelClosed { ref short_channel_id, ref is_permanent } => {
				self.network_graph.write().unwrap().close_channel_from_update(short_channel_id, &is_permanent);
			},
			&msgs::HTLCFailChannelUpdate::NodeFailure { ref node_id, ref is_permanent } => {
				self.network_graph.write().unwrap().fail_node(node_id, &is_permanent);
			},
		}
	}

	fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
		self.network_graph.write().unwrap().update_channel(msg, Some(&self.secp_ctx))
	}

	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)> {
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

	fn get_next_node_announcements(&self, starting_point: Option<&PublicKey>, batch_amount: u8) -> Vec<msgs::NodeAnnouncement> {
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
	/// Fees charged when the channel is used for routing
	pub fees: RoutingFees,
	/// Most recent update for the channel received from the network
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub last_update_message: Option<msgs::ChannelUpdate>,
}

impl std::fmt::Display for DirectionalChannelInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "last_update {}, enabled {}, cltv_expiry_delta {}, htlc_minimum_msat {}, fees {:?}", self.last_update, self.enabled, self.cltv_expiry_delta, self.htlc_minimum_msat, self.fees)?;
		Ok(())
	}
}

impl_writeable!(DirectionalChannelInfo, 0, {
	last_update,
	enabled,
	cltv_expiry_delta,
	htlc_minimum_msat,
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
	/// An initial announcement of the channel
	/// Mostly redundant with the data we store in fields explicitly.
	/// Everything else is useful only for sending out for initial routing sync.
	/// Not stored if contains excess data to prevent DoS.
	pub announcement_message: Option<msgs::ChannelAnnouncement>,
}

impl std::fmt::Display for ChannelInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
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
	pub announcement_message: Option<msgs::NodeAnnouncement>
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

impl std::fmt::Display for NodeInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
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

/// Allows for updating user's network metadata.
pub trait RouteFeePenalty {
	/// Gets a channel's fee penalty based on its channel_id (as stored in a NetworkGraph object).
	fn get_channel_fee_penalty(&self, chan_id: u64) -> u64;
	/// Informs metadata object that a route has successfully executed its payment.
	fn route_succeeded(&mut self, route: Vec<RouteHop>);
	/// Informs metadata object that a route has failed to execute a payment.
	fn route_failed(&mut self, route: Vec<RouteHop>, failed_hop: RouteHop);
}

/// A default metadata object that is used to implement the default functionality for the
/// NetworkTracker trait. A user could  make their own Metadata object and extend the
/// functionality of it by implementing other functions/traits for their metadata.
pub struct DefaultMetadata {
	/// A list of failed channels. Maps channel_id (as specified in the NetworkGraph object) to
	/// the number of successful routes to participate before being removed from the list. All
	/// channels in failed_channels are assumed to have a penalty of u64::max.
	failed_channels: BTreeMap<u64, u64>,
}

impl RouteFeePenalty for DefaultMetadata {
	fn get_channel_fee_penalty(&self, chan_id: u64) -> u64 {
		if self.failed_channels.get(&chan_id) == None {
			return 0;
		} else {
			return u64::max_value();
		}
	}

	fn route_succeeded(&mut self, route: Vec<RouteHop>) {
		for route_hop in route {
			let chan_id = route_hop.short_channel_id;
			let mut can_remove = false;
			if let Some(successes_needed) = self.failed_channels.get_mut(&chan_id) {
				*successes_needed = *successes_needed - 1;
				can_remove = *successes_needed == 0;
			}
			if can_remove {
				self.failed_channels.remove(&chan_id);
			}
		}
	}

	fn route_failed(&mut self, route: Vec<RouteHop>, failed_hop: RouteHop) {
		for route_hop in route {
			if route_hop == failed_hop {
				*self.failed_channels.entry(failed_hop.short_channel_id).or_insert(5) += 1;
				break;
			}
		}
	}
}

/// Users store custom metadata about the network separately. This trait is implemented by users, who may use
/// the NetworkGraph to update whatever metadata they are storing about their view of the network.
pub trait NetworkTracker<T: RouteFeePenalty = DefaultMetadata> {
	/// Return score for a given channel by using user-defined channel_scorers
	fn calculate_minimum_fee_penalty_for_channel(&self, chan_id: u64, network_metadata: T) -> u64 {
		return network_metadata.get_channel_fee_penalty(chan_id);
	}
}

/// Represents the network as nodes and channels between them
#[derive(PartialEq)]
pub struct NetworkGraph {
	channels: BTreeMap<u64, ChannelInfo>,
	nodes: BTreeMap<PublicKey, NodeInfo>,
}

impl Writeable for NetworkGraph {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
			channels,
			nodes,
		})
	}
}

impl std::fmt::Display for NetworkGraph {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "Network map\n[Channels]\n")?;
		for (key, val) in self.channels.iter() {
			write!(f, " {}: {}\n", key, val)?;
		}
		write!(f, "[Nodes]\n")?;
		for (key, val) in self.nodes.iter() {
			write!(f, " {}: {}\n", log_pubkey!(key), val)?;
		}
		Ok(())
	}
}

impl NetworkGraph {
	/// Returns all known valid channels' short ids along with announced channel info.
	pub fn get_channels<'a>(&'a self) -> &'a BTreeMap<u64, ChannelInfo> { &self.channels }
	/// Returns all known nodes' public keys along with announced node info.
	pub fn get_nodes<'a>(&'a self) -> &'a BTreeMap<PublicKey, NodeInfo> { &self.nodes }

	/// Get network addresses by node id.
	/// Returns None if the requested node is completely unknown,
	/// or if node announcement for the node was never received.
	pub fn get_addresses<'a>(&'a self, pubkey: &PublicKey) -> Option<&'a Vec<NetAddress>> {
		if let Some(node) = self.nodes.get(pubkey) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				return Some(&node_info.addresses)
			}
		}
		None
	}

	/// For an already known node (from channel announcements), update its stored properties from a given node announcement
	/// Announcement signatures are checked here only if Secp256k1 object is provided.
	fn update_node_from_announcement(&mut self, msg: &msgs::NodeAnnouncement, secp_ctx: Option<&Secp256k1<secp256k1::VerifyOnly>>) -> Result<bool, LightningError> {
		if let Some(sig_verifier) = secp_ctx {
			let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
			secp_verify_sig!(sig_verifier, &msg_hash, &msg.signature, &msg.contents.node_id);
		}

		match self.nodes.get_mut(&msg.contents.node_id) {
			None => Err(LightningError{err: "No existing channels for node_announcement", action: ErrorAction::IgnoreError}),
			Some(node) => {
				if let Some(node_info) = node.announcement_info.as_ref() {
					if node_info.last_update  >= msg.contents.timestamp {
						return Err(LightningError{err: "Update older than last processed update", action: ErrorAction::IgnoreError});
					}
				}

				let should_relay = msg.contents.excess_data.is_empty() && msg.contents.excess_address_data.is_empty();
				node.announcement_info = Some(NodeAnnouncementInfo {
					features: msg.contents.features.clone(),
					last_update: msg.contents.timestamp,
					rgb: msg.contents.rgb,
					alias: msg.contents.alias,
					addresses: msg.contents.addresses.clone(),
					announcement_message: if should_relay { Some(msg.clone()) } else { None },
				});

				Ok(should_relay)
			}
		}
	}

	/// For a new or already known (from previous announcement) channel, store or update channel info.
	/// Also store nodes (if not stored yet) the channel is between, and make node aware of this channel.
	/// Checking utxo on-chain is useful if we receive an update for already known channel id,
	/// which is probably result of a reorg. In that case, we update channel info only if the
	/// utxo was checked, otherwise stick to the existing update, to prevent DoS risks.
	/// Announcement signatures are checked here only if Secp256k1 object is provided.
	fn update_channel_from_announcement(&mut self, msg: &msgs::ChannelAnnouncement, checked_utxo: bool, secp_ctx: Option<&Secp256k1<secp256k1::VerifyOnly>>) -> Result<bool, LightningError> {
		if let Some(sig_verifier) = secp_ctx {
			let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
			secp_verify_sig!(sig_verifier, &msg_hash, &msg.node_signature_1, &msg.contents.node_id_1);
			secp_verify_sig!(sig_verifier, &msg_hash, &msg.node_signature_2, &msg.contents.node_id_2);
			secp_verify_sig!(sig_verifier, &msg_hash, &msg.bitcoin_signature_1, &msg.contents.bitcoin_key_1);
			secp_verify_sig!(sig_verifier, &msg_hash, &msg.bitcoin_signature_2, &msg.contents.bitcoin_key_2);
		}

		let should_relay = msg.contents.excess_data.is_empty();

		let chan_info = ChannelInfo {
				features: msg.contents.features.clone(),
				node_one: msg.contents.node_id_1.clone(),
				one_to_two: None,
				node_two: msg.contents.node_id_2.clone(),
				two_to_one: None,
				announcement_message: if should_relay { Some(msg.clone()) } else { None },
			};

		match self.channels.entry(msg.contents.short_channel_id) {
			BtreeEntry::Occupied(mut entry) => {
				//TODO: because asking the blockchain if short_channel_id is valid is only optional
				//in the blockchain API, we need to handle it smartly here, though it's unclear
				//exactly how...
				if checked_utxo {
					// Either our UTXO provider is busted, there was a reorg, or the UTXO provider
					// only sometimes returns results. In any case remove the previous entry. Note
					// that the spec expects us to "blacklist" the node_ids involved, but we can't
					// do that because
					// a) we don't *require* a UTXO provider that always returns results.
					// b) we don't track UTXOs of channels we know about and remove them if they
					//    get reorg'd out.
					// c) it's unclear how to do so without exposing ourselves to massive DoS risk.
					Self::remove_channel_in_nodes(&mut self.nodes, &entry.get(), msg.contents.short_channel_id);
					*entry.get_mut() = chan_info;
				} else {
					return Err(LightningError{err: "Already have knowledge of channel", action: ErrorAction::IgnoreError})
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
						node_entry.into_mut().channels.push(msg.contents.short_channel_id);
					},
					BtreeEntry::Vacant(node_entry) => {
						node_entry.insert(NodeInfo {
							channels: vec!(msg.contents.short_channel_id),
							lowest_inbound_channel_fees: None,
							announcement_info: None,
						});
					}
				}
			};
		}

		add_channel_to_node!(msg.contents.node_id_1);
		add_channel_to_node!(msg.contents.node_id_2);

		Ok(should_relay)
	}

	/// Close a channel if a corresponding HTLC fail was sent.
	/// If permanent, removes a channel from the local storage.
	/// May cause the removal of nodes too, if this was their last channel.
	/// If not permanent, makes channels unavailable for routing.
	pub fn close_channel_from_update(&mut self, short_channel_id: &u64, is_permanent: &bool) {
		if *is_permanent {
			if let Some(chan) = self.channels.remove(short_channel_id) {
				Self::remove_channel_in_nodes(&mut self.nodes, &chan, *short_channel_id);
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

	fn fail_node(&mut self, _node_id: &PublicKey, is_permanent: &bool) {
		if *is_permanent {
			// TODO: Wholly remove the node
		} else {
			// TODO: downgrade the node
		}
	}

	/// For an already known (from announcement) channel, update info about one of the directions of a channel.
	/// Announcement signatures are checked here only if Secp256k1 object is provided.
	fn update_channel(&mut self, msg: &msgs::ChannelUpdate, secp_ctx: Option<&Secp256k1<secp256k1::VerifyOnly>>) -> Result<bool, LightningError> {
		let dest_node_id;
		let chan_enabled = msg.contents.flags & (1 << 1) != (1 << 1);
		let chan_was_enabled;

		match self.channels.get_mut(&msg.contents.short_channel_id) {
			None => return Err(LightningError{err: "Couldn't find channel for update", action: ErrorAction::IgnoreError}),
			Some(channel) => {
				macro_rules! maybe_update_channel_info {
					( $target: expr, $src_node: expr) => {
						if let Some(existing_chan_info) = $target.as_ref() {
							if existing_chan_info.last_update >= msg.contents.timestamp {
								return Err(LightningError{err: "Update older than last processed update", action: ErrorAction::IgnoreError});
							}
							chan_was_enabled = existing_chan_info.enabled;
						} else {
							chan_was_enabled = false;
						}

						let last_update_message = if msg.contents.excess_data.is_empty() {
							Some(msg.clone())
						} else {
							None
						};

						let updated_channel_dir_info = DirectionalChannelInfo {
							enabled: chan_enabled,
							last_update: msg.contents.timestamp,
							cltv_expiry_delta: msg.contents.cltv_expiry_delta,
							htlc_minimum_msat: msg.contents.htlc_minimum_msat,
							fees: RoutingFees {
								base_msat: msg.contents.fee_base_msat,
								proportional_millionths: msg.contents.fee_proportional_millionths,
							},
							last_update_message
						};
						$target = Some(updated_channel_dir_info);
					}
				}

				let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
				if msg.contents.flags & 1 == 1 {
					dest_node_id = channel.node_one.clone();
					if let Some(sig_verifier) = secp_ctx {
						secp_verify_sig!(sig_verifier, &msg_hash, &msg.signature, &channel.node_two);
					}
					maybe_update_channel_info!(channel.two_to_one, channel.node_two);
				} else {
					dest_node_id = channel.node_two.clone();
					if let Some(sig_verifier) = secp_ctx {
						secp_verify_sig!(sig_verifier, &msg_hash, &msg.signature, &channel.node_one);
					}
					maybe_update_channel_info!(channel.one_to_two, channel.node_one);
				}
			}
		}

		if chan_enabled {
			let node = self.nodes.get_mut(&dest_node_id).unwrap();
			let mut base_msat = msg.contents.fee_base_msat;
			let mut proportional_millionths = msg.contents.fee_proportional_millionths;
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

		Ok(msg.contents.excess_data.is_empty())
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
	use chain::chaininterface;
	use ln::features::{ChannelFeatures, NodeFeatures};
	use routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
	use ln::msgs::{RoutingMessageHandler, UnsignedNodeAnnouncement, NodeAnnouncement,
		UnsignedChannelAnnouncement, ChannelAnnouncement, UnsignedChannelUpdate, ChannelUpdate, HTLCFailChannelUpdate};
	use util::test_utils;
	use util::logger::Logger;
	use util::ser::{Readable, Writeable};

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::util::hash::BitcoinHash;

	use hex;

	use bitcoin::secp256k1::key::{PublicKey, SecretKey};
	use bitcoin::secp256k1::{All, Secp256k1};

	use std::sync::Arc;

	fn create_net_graph_msg_handler() -> (Secp256k1<All>, NetGraphMsgHandler<Arc<chaininterface::ChainWatchInterfaceUtil>, Arc<test_utils::TestLogger>>) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet));
		let net_graph_msg_handler = NetGraphMsgHandler::new(chain_monitor, Arc::clone(&logger));
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
				chain_hash: genesis_block(Network::Testnet).header.bitcoin_hash(),
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
		let chain_monitor = Arc::new(test_utils::TestChainWatcher::new());
		let net_graph_msg_handler = NetGraphMsgHandler::new(chain_monitor.clone(), Arc::clone(&logger));


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
			chain_hash: genesis_block(Network::Testnet).header.bitcoin_hash(),
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
		*chain_monitor.utxo_ret.lock().unwrap() = Err(chaininterface::ChainError::NotSupported);

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
		*chain_monitor.utxo_ret.lock().unwrap() = Err(chaininterface::ChainError::UnknownTx);
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
		*chain_monitor.utxo_ret.lock().unwrap() = Ok((good_script.clone(), 0));

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
		*chain_monitor.utxo_ret.lock().unwrap() = Err(chaininterface::ChainError::UnknownTx);
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e.err, "Channel announced without corresponding UTXO entry")
		};

		// But if it is confirmed, replace the channel
		*chain_monitor.utxo_ret.lock().unwrap() = Ok((good_script, 0));
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
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_1_privkey),
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
		let (secp_ctx, net_graph_msg_handler) = create_net_graph_msg_handler();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);
		let node_1_btckey = &SecretKey::from_slice(&[40; 32]).unwrap();
		let node_2_btckey = &SecretKey::from_slice(&[39; 32]).unwrap();

		let zero_hash = Sha256dHash::hash(&[0; 32]);
		let short_channel_id = 0;
		let chain_hash = genesis_block(Network::Testnet).header.bitcoin_hash();
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

		let mut unsigned_channel_update = UnsignedChannelUpdate {
			chain_hash,
			short_channel_id,
			timestamp: 100,
			flags: 0,
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1000000,
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
		let chain_hash = genesis_block(Network::Testnet).header.bitcoin_hash();

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
		let chain_hash = genesis_block(Network::Testnet).header.bitcoin_hash();

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
		let chain_hash = genesis_block(Network::Testnet).header.bitcoin_hash();

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
			chain_hash: genesis_block(Network::Testnet).header.bitcoin_hash(),
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
}
