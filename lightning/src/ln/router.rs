//! The top-level routing/network map tracking logic lives here.
//!
//! You probably want to create a Router and use that as your RoutingMessageHandler and then
//! interrogate it to get routes for your own payments.

use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;
use secp256k1;

use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;

use chain::chaininterface::{ChainError, ChainWatchInterface};
use ln::channelmanager;
use ln::msgs::{DecodeError,ErrorAction,HandleError,RoutingMessageHandler,NetAddress,GlobalFeatures};
use ln::msgs;
use util::ser::{Writeable, Readable, Writer, ReadableArgs};
use util::logger::Logger;

use std::cmp;
use std::sync::{RwLock,Arc};
use std::collections::{HashMap,BinaryHeap,BTreeMap};
use std::collections::btree_map::Entry as BtreeEntry;
use std;

/// A hop in a route
#[derive(Clone, PartialEq)]
pub struct RouteHop {
	/// The node_id of the node at this hop.
	pub pubkey: PublicKey,
	/// The channel that should be used from the previous hop to reach this node.
	pub short_channel_id: u64,
	/// The fee taken on this hop. For the last hop, this should be the full value of the payment.
	pub fee_msat: u64,
	/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
	/// expected at the destination, in excess of the current block height.
	pub cltv_expiry_delta: u32,
}

/// A route from us through the network to a destination
#[derive(Clone, PartialEq)]
pub struct Route {
	/// The list of hops, NOT INCLUDING our own, where the last hop is the destination. Thus, this
	/// must always be at least length one. By protocol rules, this may not currently exceed 20 in
	/// length.
	pub hops: Vec<RouteHop>,
}

impl Writeable for Route {
	fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.hops.len() as u8).write(writer)?;
		for hop in self.hops.iter() {
			hop.pubkey.write(writer)?;
			hop.short_channel_id.write(writer)?;
			hop.fee_msat.write(writer)?;
			hop.cltv_expiry_delta.write(writer)?;
		}
		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for Route {
	fn read(reader: &mut R) -> Result<Route, DecodeError> {
		let hops_count: u8 = Readable::read(reader)?;
		let mut hops = Vec::with_capacity(hops_count as usize);
		for _ in 0..hops_count {
			hops.push(RouteHop {
				pubkey: Readable::read(reader)?,
				short_channel_id: Readable::read(reader)?,
				fee_msat: Readable::read(reader)?,
				cltv_expiry_delta: Readable::read(reader)?,
			});
		}
		Ok(Route {
			hops
		})
	}
}

#[derive(PartialEq)]
struct DirectionalChannelInfo {
	src_node_id: PublicKey,
	last_update: u32,
	enabled: bool,
	cltv_expiry_delta: u16,
	htlc_minimum_msat: u64,
	fee_base_msat: u32,
	fee_proportional_millionths: u32,
	last_update_message: Option<msgs::ChannelUpdate>,
}

impl std::fmt::Display for DirectionalChannelInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "src_node_id {}, last_update {}, enabled {}, cltv_expiry_delta {}, htlc_minimum_msat {}, fee_base_msat {}, fee_proportional_millionths {}", log_pubkey!(self.src_node_id), self.last_update, self.enabled, self.cltv_expiry_delta, self.htlc_minimum_msat, self.fee_base_msat, self.fee_proportional_millionths)?;
		Ok(())
	}
}

impl_writeable!(DirectionalChannelInfo, 0, {
	src_node_id,
	last_update,
	enabled,
	cltv_expiry_delta,
	htlc_minimum_msat,
	fee_base_msat,
	fee_proportional_millionths,
	last_update_message
});

#[derive(PartialEq)]
struct ChannelInfo {
	features: GlobalFeatures,
	one_to_two: DirectionalChannelInfo,
	two_to_one: DirectionalChannelInfo,
	//this is cached here so we can send out it later if required by route_init_sync
	//keep an eye on this to see if the extra memory is a problem
	announcement_message: Option<msgs::ChannelAnnouncement>,
}

impl std::fmt::Display for ChannelInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "features: {}, one_to_two: {}, two_to_one: {}", log_bytes!(self.features.encode()), self.one_to_two, self.two_to_one)?;
		Ok(())
	}
}

impl_writeable!(ChannelInfo, 0, {
	features,
	one_to_two,
	two_to_one,
	announcement_message
});

#[derive(PartialEq)]
struct NodeInfo {
	#[cfg(feature = "non_bitcoin_chain_hash_routing")]
	channels: Vec<(u64, Sha256dHash)>,
	#[cfg(not(feature = "non_bitcoin_chain_hash_routing"))]
	channels: Vec<u64>,

	lowest_inbound_channel_fee_base_msat: u32,
	lowest_inbound_channel_fee_proportional_millionths: u32,

	features: GlobalFeatures,
	last_update: u32,
	rgb: [u8; 3],
	alias: [u8; 32],
	addresses: Vec<NetAddress>,
	//this is cached here so we can send out it later if required by route_init_sync
	//keep an eye on this to see if the extra memory is a problem
	announcement_message: Option<msgs::NodeAnnouncement>,
}

impl std::fmt::Display for NodeInfo {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "features: {}, last_update: {}, lowest_inbound_channel_fee_base_msat: {}, lowest_inbound_channel_fee_proportional_millionths: {}, channels: {:?}", log_bytes!(self.features.encode()), self.last_update, self.lowest_inbound_channel_fee_base_msat, self.lowest_inbound_channel_fee_proportional_millionths, &self.channels[..])?;
		Ok(())
	}
}

impl Writeable for NodeInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.channels.len() as u64).write(writer)?;
		for ref chan in self.channels.iter() {
			chan.write(writer)?;
		}
		self.lowest_inbound_channel_fee_base_msat.write(writer)?;
		self.lowest_inbound_channel_fee_proportional_millionths.write(writer)?;
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

const MAX_ALLOC_SIZE: u64 = 64*1024;

impl<R: ::std::io::Read> Readable<R> for NodeInfo {
	fn read(reader: &mut R) -> Result<NodeInfo, DecodeError> {
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = Vec::with_capacity(cmp::min(channels_count, MAX_ALLOC_SIZE / 8) as usize);
		for _ in 0..channels_count {
			channels.push(Readable::read(reader)?);
		}
		let lowest_inbound_channel_fee_base_msat = Readable::read(reader)?;
		let lowest_inbound_channel_fee_proportional_millionths = Readable::read(reader)?;
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
		Ok(NodeInfo {
			channels,
			lowest_inbound_channel_fee_base_msat,
			lowest_inbound_channel_fee_proportional_millionths,
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
struct NetworkMap {
	#[cfg(feature = "non_bitcoin_chain_hash_routing")]
	channels: BTreeMap<(u64, Sha256dHash), ChannelInfo>,
	#[cfg(not(feature = "non_bitcoin_chain_hash_routing"))]
	channels: BTreeMap<u64, ChannelInfo>,

	our_node_id: PublicKey,
	nodes: BTreeMap<PublicKey, NodeInfo>,
}

impl Writeable for NetworkMap {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.channels.len() as u64).write(writer)?;
		for (ref chan_id, ref chan_info) in self.channels.iter() {
			(*chan_id).write(writer)?;
			chan_info.write(writer)?;
		}
		self.our_node_id.write(writer)?;
		(self.nodes.len() as u64).write(writer)?;
		for (ref node_id, ref node_info) in self.nodes.iter() {
			node_id.write(writer)?;
			node_info.write(writer)?;
		}
		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for NetworkMap {
	fn read(reader: &mut R) -> Result<NetworkMap, DecodeError> {
		let channels_count: u64 = Readable::read(reader)?;
		let mut channels = BTreeMap::new();
		for _ in 0..channels_count {
			let chan_id: u64 = Readable::read(reader)?;
			let chan_info = Readable::read(reader)?;
			channels.insert(chan_id, chan_info);
		}
		let our_node_id = Readable::read(reader)?;
		let nodes_count: u64 = Readable::read(reader)?;
		let mut nodes = BTreeMap::new();
		for _ in 0..nodes_count {
			let node_id = Readable::read(reader)?;
			let node_info = Readable::read(reader)?;
			nodes.insert(node_id, node_info);
		}
		Ok(NetworkMap {
			channels,
			our_node_id,
			nodes,
		})
	}
}

struct MutNetworkMap<'a> {
	#[cfg(feature = "non_bitcoin_chain_hash_routing")]
	channels: &'a mut BTreeMap<(u64, Sha256dHash), ChannelInfo>,
	#[cfg(not(feature = "non_bitcoin_chain_hash_routing"))]
	channels: &'a mut BTreeMap<u64, ChannelInfo>,
	nodes: &'a mut BTreeMap<PublicKey, NodeInfo>,
}
impl NetworkMap {
	fn borrow_parts(&mut self) -> MutNetworkMap {
		MutNetworkMap {
			channels: &mut self.channels,
			nodes: &mut self.nodes,
		}
	}
}
impl std::fmt::Display for NetworkMap {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "Node id {} network map\n[Channels]\n", log_pubkey!(self.our_node_id))?;
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

impl NetworkMap {
	#[cfg(feature = "non_bitcoin_chain_hash_routing")]
	#[inline]
	fn get_key(short_channel_id: u64, chain_hash: Sha256dHash) -> (u64, Sha256dHash) {
		(short_channel_id, chain_hash)
	}

	#[cfg(not(feature = "non_bitcoin_chain_hash_routing"))]
	#[inline]
	fn get_key(short_channel_id: u64, _: Sha256dHash) -> u64 {
		short_channel_id
	}

	#[cfg(feature = "non_bitcoin_chain_hash_routing")]
	#[inline]
	fn get_short_id(id: &(u64, Sha256dHash)) -> &u64 {
		&id.0
	}

	#[cfg(not(feature = "non_bitcoin_chain_hash_routing"))]
	#[inline]
	fn get_short_id(id: &u64) -> &u64 {
		id
	}
}

/// A channel descriptor which provides a last-hop route to get_route
pub struct RouteHint {
	/// The node_id of the non-target end of the route
	pub src_node_id: PublicKey,
	/// The short_channel_id of this channel
	pub short_channel_id: u64,
	/// The static msat-denominated fee which must be paid to use this channel
	pub fee_base_msat: u32,
	/// The dynamic proportional fee which must be paid to use this channel, denominated in
	/// millionths of the value being forwarded to the next hop.
	pub fee_proportional_millionths: u32,
	/// The difference in CLTV values between this node and the next node.
	pub cltv_expiry_delta: u16,
	/// The minimum value, in msat, which must be relayed to the next hop.
	pub htlc_minimum_msat: u64,
}

/// Tracks a view of the network, receiving updates from peers and generating Routes to
/// payment destinations.
pub struct Router {
	secp_ctx: Secp256k1<secp256k1::VerifyOnly>,
	network_map: RwLock<NetworkMap>,
	chain_monitor: Arc<ChainWatchInterface>,
	logger: Arc<Logger>,
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for Router {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		writer.write_all(&[SERIALIZATION_VERSION; 1])?;
		writer.write_all(&[MIN_SERIALIZATION_VERSION; 1])?;

		let network = self.network_map.read().unwrap();
		network.write(writer)?;
		Ok(())
	}
}

/// Arguments for the creation of a Router that are not deserialized.
/// At a high-level, the process for deserializing a Router and resuming normal operation is:
/// 1) Deserialize the Router by filling in this struct and calling <Router>::read(reaser, args).
/// 2) Register the new Router with your ChainWatchInterface
pub struct RouterReadArgs {
	/// The ChainWatchInterface for use in the Router in the future.
	///
	/// No calls to the ChainWatchInterface will be made during deserialization.
	pub chain_monitor: Arc<ChainWatchInterface>,
	/// The Logger for use in the ChannelManager and which may be used to log information during
	/// deserialization.
	pub logger: Arc<Logger>,
}

impl<R: ::std::io::Read> ReadableArgs<R, RouterReadArgs> for Router {
	fn read(reader: &mut R, args: RouterReadArgs) -> Result<Router, DecodeError> {
		let _ver: u8 = Readable::read(reader)?;
		let min_ver: u8 = Readable::read(reader)?;
		if min_ver > SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}
		let network_map = Readable::read(reader)?;
		Ok(Router {
			secp_ctx: Secp256k1::verification_only(),
			network_map: RwLock::new(network_map),
			chain_monitor: args.chain_monitor,
			logger: args.logger,
		})
	}
}

macro_rules! secp_verify_sig {
	( $secp_ctx: expr, $msg: expr, $sig: expr, $pubkey: expr ) => {
		match $secp_ctx.verify($msg, $sig, $pubkey) {
			Ok(_) => {},
			Err(_) => return Err(HandleError{err: "Invalid signature from remote node", action: None}),
		}
	};
}

impl RoutingMessageHandler for Router {
	fn handle_node_announcement(&self, msg: &msgs::NodeAnnouncement) -> Result<bool, HandleError> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.signature, &msg.contents.node_id);

		if msg.contents.features.requires_unknown_bits() {
			panic!("Unknown-required-features NodeAnnouncements should never deserialize!");
		}

		let mut network = self.network_map.write().unwrap();
		match network.nodes.get_mut(&msg.contents.node_id) {
			None => Err(HandleError{err: "No existing channels for node_announcement", action: Some(ErrorAction::IgnoreError)}),
			Some(node) => {
				if node.last_update >= msg.contents.timestamp {
					return Err(HandleError{err: "Update older than last processed update", action: Some(ErrorAction::IgnoreError)});
				}

				node.features = msg.contents.features.clone();
				node.last_update = msg.contents.timestamp;
				node.rgb = msg.contents.rgb;
				node.alias = msg.contents.alias;
				node.addresses = msg.contents.addresses.clone();

				let should_relay = msg.contents.excess_data.is_empty() && msg.contents.excess_address_data.is_empty() && !msg.contents.features.supports_unknown_bits();
				node.announcement_message = if should_relay { Some(msg.clone()) } else { None };
				Ok(should_relay)
			}
		}
	}

	fn handle_channel_announcement(&self, msg: &msgs::ChannelAnnouncement) -> Result<bool, HandleError> {
		if msg.contents.node_id_1 == msg.contents.node_id_2 || msg.contents.bitcoin_key_1 == msg.contents.bitcoin_key_2 {
			return Err(HandleError{err: "Channel announcement node had a channel with itself", action: Some(ErrorAction::IgnoreError)});
		}

		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.node_signature_1, &msg.contents.node_id_1);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.node_signature_2, &msg.contents.node_id_2);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.bitcoin_signature_1, &msg.contents.bitcoin_key_1);
		secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.bitcoin_signature_2, &msg.contents.bitcoin_key_2);

		if msg.contents.features.requires_unknown_bits() {
			panic!("Unknown-required-features ChannelAnnouncements should never deserialize!");
		}

		let checked_utxo = match self.chain_monitor.get_chain_utxo(msg.contents.chain_hash, msg.contents.short_channel_id) {
			Ok((script_pubkey, _value)) => {
				let expected_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
				                                    .push_slice(&msg.contents.bitcoin_key_1.serialize())
				                                    .push_slice(&msg.contents.bitcoin_key_2.serialize())
				                                    .push_opcode(opcodes::all::OP_PUSHNUM_2)
				                                    .push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();
				if script_pubkey != expected_script {
					return Err(HandleError{err: "Channel announcement keys didn't match on-chain script", action: Some(ErrorAction::IgnoreError)});
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
				return Err(HandleError{err: "Channel announced on an unknown chain", action: Some(ErrorAction::IgnoreError)});
			},
			Err(ChainError::UnknownTx) => {
				return Err(HandleError{err: "Channel announced without corresponding UTXO entry", action: Some(ErrorAction::IgnoreError)});
			},
		};

		let mut network_lock = self.network_map.write().unwrap();
		let network = network_lock.borrow_parts();

		let should_relay = msg.contents.excess_data.is_empty() && !msg.contents.features.supports_unknown_bits();

		let chan_info = ChannelInfo {
				features: msg.contents.features.clone(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: msg.contents.node_id_1.clone(),
					last_update: 0,
					enabled: false,
					cltv_expiry_delta: u16::max_value(),
					htlc_minimum_msat: u64::max_value(),
					fee_base_msat: u32::max_value(),
					fee_proportional_millionths: u32::max_value(),
					last_update_message: None,
				},
				two_to_one: DirectionalChannelInfo {
					src_node_id: msg.contents.node_id_2.clone(),
					last_update: 0,
					enabled: false,
					cltv_expiry_delta: u16::max_value(),
					htlc_minimum_msat: u64::max_value(),
					fee_base_msat: u32::max_value(),
					fee_proportional_millionths: u32::max_value(),
					last_update_message: None,
				},
				announcement_message: if should_relay { Some(msg.clone()) } else { None },
			};

		match network.channels.entry(NetworkMap::get_key(msg.contents.short_channel_id, msg.contents.chain_hash)) {
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
					Self::remove_channel_in_nodes(network.nodes, &entry.get(), msg.contents.short_channel_id);
					*entry.get_mut() = chan_info;
				} else {
					return Err(HandleError{err: "Already have knowledge of channel", action: Some(ErrorAction::IgnoreError)})
				}
			},
			BtreeEntry::Vacant(entry) => {
				entry.insert(chan_info);
			}
		};

		macro_rules! add_channel_to_node {
			( $node_id: expr ) => {
				match network.nodes.entry($node_id) {
					BtreeEntry::Occupied(node_entry) => {
						node_entry.into_mut().channels.push(NetworkMap::get_key(msg.contents.short_channel_id, msg.contents.chain_hash));
					},
					BtreeEntry::Vacant(node_entry) => {
						node_entry.insert(NodeInfo {
							channels: vec!(NetworkMap::get_key(msg.contents.short_channel_id, msg.contents.chain_hash)),
							lowest_inbound_channel_fee_base_msat: u32::max_value(),
							lowest_inbound_channel_fee_proportional_millionths: u32::max_value(),
							features: GlobalFeatures::new(),
							last_update: 0,
							rgb: [0; 3],
							alias: [0; 32],
							addresses: Vec::new(),
							announcement_message: None,
						});
					}
				}
			};
		}

		add_channel_to_node!(msg.contents.node_id_1);
		add_channel_to_node!(msg.contents.node_id_2);

		Ok(should_relay)
	}

	fn handle_htlc_fail_channel_update(&self, update: &msgs::HTLCFailChannelUpdate) {
		match update {
			&msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg } => {
				let _ = self.handle_channel_update(msg);
			},
			&msgs::HTLCFailChannelUpdate::ChannelClosed { ref short_channel_id, ref is_permanent } => {
				let mut network = self.network_map.write().unwrap();
				if *is_permanent {
					if let Some(chan) = network.channels.remove(short_channel_id) {
						Self::remove_channel_in_nodes(&mut network.nodes, &chan, *short_channel_id);
					}
				} else {
					if let Some(chan) = network.channels.get_mut(short_channel_id) {
						chan.one_to_two.enabled = false;
						chan.two_to_one.enabled = false;
					}
				}
			},
			&msgs::HTLCFailChannelUpdate::NodeFailure { ref node_id, ref is_permanent } => {
				if *is_permanent {
					//TODO: Wholly remove the node
				} else {
					self.mark_node_bad(node_id, false);
				}
			},
		}
	}

	fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, HandleError> {
		let mut network = self.network_map.write().unwrap();
		let dest_node_id;
		let chan_enabled = msg.contents.flags & (1 << 1) != (1 << 1);
		let chan_was_enabled;

		match network.channels.get_mut(&NetworkMap::get_key(msg.contents.short_channel_id, msg.contents.chain_hash)) {
			None => return Err(HandleError{err: "Couldn't find channel for update", action: Some(ErrorAction::IgnoreError)}),
			Some(channel) => {
				macro_rules! maybe_update_channel_info {
					( $target: expr) => {
						if $target.last_update >= msg.contents.timestamp {
							return Err(HandleError{err: "Update older than last processed update", action: Some(ErrorAction::IgnoreError)});
						}
						chan_was_enabled = $target.enabled;
						$target.last_update = msg.contents.timestamp;
						$target.enabled = chan_enabled;
						$target.cltv_expiry_delta = msg.contents.cltv_expiry_delta;
						$target.htlc_minimum_msat = msg.contents.htlc_minimum_msat;
						$target.fee_base_msat = msg.contents.fee_base_msat;
						$target.fee_proportional_millionths = msg.contents.fee_proportional_millionths;
						$target.last_update_message = if msg.contents.excess_data.is_empty() {
							Some(msg.clone())
						} else {
							None
						};
					}
				}
				let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.contents.encode()[..])[..]);
				if msg.contents.flags & 1 == 1 {
					dest_node_id = channel.one_to_two.src_node_id.clone();
					secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.signature, &channel.two_to_one.src_node_id);
					maybe_update_channel_info!(channel.two_to_one);
				} else {
					dest_node_id = channel.two_to_one.src_node_id.clone();
					secp_verify_sig!(self.secp_ctx, &msg_hash, &msg.signature, &channel.one_to_two.src_node_id);
					maybe_update_channel_info!(channel.one_to_two);
				}
			}
		}

		if chan_enabled {
			let node = network.nodes.get_mut(&dest_node_id).unwrap();
			node.lowest_inbound_channel_fee_base_msat = cmp::min(node.lowest_inbound_channel_fee_base_msat, msg.contents.fee_base_msat);
			node.lowest_inbound_channel_fee_proportional_millionths = cmp::min(node.lowest_inbound_channel_fee_proportional_millionths, msg.contents.fee_proportional_millionths);
		} else if chan_was_enabled {
			let mut lowest_inbound_channel_fee_base_msat = u32::max_value();
			let mut lowest_inbound_channel_fee_proportional_millionths = u32::max_value();

			{
				let node = network.nodes.get(&dest_node_id).unwrap();

				for chan_id in node.channels.iter() {
					let chan = network.channels.get(chan_id).unwrap();
					if chan.one_to_two.src_node_id == dest_node_id {
						lowest_inbound_channel_fee_base_msat = cmp::min(lowest_inbound_channel_fee_base_msat, chan.two_to_one.fee_base_msat);
						lowest_inbound_channel_fee_proportional_millionths = cmp::min(lowest_inbound_channel_fee_proportional_millionths, chan.two_to_one.fee_proportional_millionths);
					} else {
						lowest_inbound_channel_fee_base_msat = cmp::min(lowest_inbound_channel_fee_base_msat, chan.one_to_two.fee_base_msat);
						lowest_inbound_channel_fee_proportional_millionths = cmp::min(lowest_inbound_channel_fee_proportional_millionths, chan.one_to_two.fee_proportional_millionths);
					}
				}
			}

			//TODO: satisfy the borrow-checker without a double-map-lookup :(
			let mut_node = network.nodes.get_mut(&dest_node_id).unwrap();
			mut_node.lowest_inbound_channel_fee_base_msat = lowest_inbound_channel_fee_base_msat;
			mut_node.lowest_inbound_channel_fee_proportional_millionths = lowest_inbound_channel_fee_proportional_millionths;
		}

		Ok(msg.contents.excess_data.is_empty())
	}


	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(msgs::ChannelAnnouncement, msgs::ChannelUpdate,msgs::ChannelUpdate)> {
		let mut result = Vec::with_capacity(batch_amount as usize);
		let network = self.network_map.read().unwrap();
		let mut iter = network.channels.range(starting_point..);
		while result.len() < batch_amount as usize {
			if let Some((_, ref chan)) = iter.next() {
				if chan.announcement_message.is_some() &&
						chan.one_to_two.last_update_message.is_some() &&
						chan.two_to_one.last_update_message.is_some() {
					result.push((chan.announcement_message.clone().unwrap(),
						chan.one_to_two.last_update_message.clone().unwrap(),
						chan.two_to_one.last_update_message.clone().unwrap()));
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
		let mut result = Vec::with_capacity(batch_amount as usize);
		let network = self.network_map.read().unwrap();
		let mut iter = if let Some(pubkey) = starting_point {
				let mut iter = network.nodes.range((*pubkey)..);
				iter.next();
				iter
			} else {
				network.nodes.range(..)
			};
		while result.len() < batch_amount as usize {
			if let Some((_, ref node)) = iter.next() {
				if node.announcement_message.is_some() {
					result.push(node.announcement_message.clone().unwrap());
				}
			} else {
				return result;
			}
		}
		result
	}
}

#[derive(Eq, PartialEq)]
struct RouteGraphNode {
	pubkey: PublicKey,
	lowest_fee_to_peer_through_node: u64,
	lowest_fee_to_node: u64,
}

impl cmp::Ord for RouteGraphNode {
	fn cmp(&self, other: &RouteGraphNode) -> cmp::Ordering {
		other.lowest_fee_to_peer_through_node.cmp(&self.lowest_fee_to_peer_through_node)
			.then_with(|| other.pubkey.serialize().cmp(&self.pubkey.serialize()))
	}
}

impl cmp::PartialOrd for RouteGraphNode {
	fn partial_cmp(&self, other: &RouteGraphNode) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

struct DummyDirectionalChannelInfo {
	src_node_id: PublicKey,
	cltv_expiry_delta: u32,
	htlc_minimum_msat: u64,
	fee_base_msat: u32,
	fee_proportional_millionths: u32,
}

impl Router {
	/// Creates a new router with the given node_id to be used as the source for get_route()
	pub fn new(our_pubkey: PublicKey, chain_monitor: Arc<ChainWatchInterface>, logger: Arc<Logger>) -> Router {
		let mut nodes = BTreeMap::new();
		nodes.insert(our_pubkey.clone(), NodeInfo {
			channels: Vec::new(),
			lowest_inbound_channel_fee_base_msat: u32::max_value(),
			lowest_inbound_channel_fee_proportional_millionths: u32::max_value(),
			features: GlobalFeatures::new(),
			last_update: 0,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			announcement_message: None,
		});
		Router {
			secp_ctx: Secp256k1::verification_only(),
			network_map: RwLock::new(NetworkMap {
				channels: BTreeMap::new(),
				our_node_id: our_pubkey,
				nodes: nodes,
			}),
			chain_monitor,
			logger,
		}
	}

	/// Dumps the entire network view of this Router to the logger provided in the constructor at
	/// level Trace
	pub fn trace_state(&self) {
		log_trace!(self, "{}", self.network_map.read().unwrap());
	}

	/// Get network addresses by node id
	pub fn get_addresses(&self, pubkey: &PublicKey) -> Option<Vec<NetAddress>> {
		let network = self.network_map.read().unwrap();
		network.nodes.get(pubkey).map(|n| n.addresses.clone())
	}

	/// Marks a node as having failed a route. This will avoid re-using the node in routes for now,
	/// with an exponential decay in node "badness". Note that there is deliberately no
	/// mark_channel_bad as a node may simply lie and suggest that an upstream channel from it is
	/// what failed the route and not the node itself. Instead, setting the blamed_upstream_node
	/// boolean will reduce the penalty, returning the node to usability faster. If the node is
	/// behaving correctly, it will disable the failing channel and we will use it again next time.
	pub fn mark_node_bad(&self, _node_id: &PublicKey, _blamed_upstream_node: bool) {
		unimplemented!();
	}

	fn remove_channel_in_nodes(nodes: &mut BTreeMap<PublicKey, NodeInfo>, chan: &ChannelInfo, short_channel_id: u64) {
		macro_rules! remove_from_node {
			($node_id: expr) => {
				if let BtreeEntry::Occupied(mut entry) = nodes.entry($node_id) {
					entry.get_mut().channels.retain(|chan_id| {
						short_channel_id != *NetworkMap::get_short_id(chan_id)
					});
					if entry.get().channels.is_empty() {
						entry.remove_entry();
					}
				} else {
					panic!("Had channel that pointed to unknown node (ie inconsistent network map)!");
				}
			}
		}
		remove_from_node!(chan.one_to_two.src_node_id);
		remove_from_node!(chan.two_to_one.src_node_id);
	}

	/// Gets a route from us to the given target node.
	///
	/// Extra routing hops between known nodes and the target will be used if they are included in
	/// last_hops.
	///
	/// If some channels aren't announced, it may be useful to fill in a first_hops with the
	/// results from a local ChannelManager::list_usable_channels() call. If it is filled in, our
	/// (this Router's) view of our local channels will be ignored, and only those in first_hops
	/// will be used.
	///
	/// Panics if first_hops contains channels without short_channel_ids
	/// (ChannelManager::list_usable_channels will never include such channels).
	///
	/// The fees on channels from us to next-hops are ignored (as they are assumed to all be
	/// equal), however the enabled/disabled bit on such channels as well as the htlc_minimum_msat
	/// *is* checked as they may change based on the receiving node.
	pub fn get_route(&self, target: &PublicKey, first_hops: Option<&[channelmanager::ChannelDetails]>, last_hops: &[RouteHint], final_value_msat: u64, final_cltv: u32) -> Result<Route, HandleError> {
		// TODO: Obviously *only* using total fee cost sucks. We should consider weighting by
		// uptime/success in using a node in the past.
		let network = self.network_map.read().unwrap();

		if *target == network.our_node_id {
			return Err(HandleError{err: "Cannot generate a route to ourselves", action: None});
		}

		if final_value_msat > 21_000_000 * 1_0000_0000 * 1000 {
			return Err(HandleError{err: "Cannot generate a route of more value than all existing satoshis", action: None});
		}

		// We do a dest-to-source Dijkstra's sorting by each node's distance from the destination
		// plus the minimum per-HTLC fee to get from it to another node (aka "shitty A*").
		// TODO: There are a few tweaks we could do, including possibly pre-calculating more stuff
		// to use as the A* heuristic beyond just the cost to get one node further than the current
		// one.

		let dummy_directional_info = DummyDirectionalChannelInfo { // used for first_hops routes
			src_node_id: network.our_node_id.clone(),
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
		};

		let mut targets = BinaryHeap::new(); //TODO: Do we care about switching to eg Fibbonaci heap?
		let mut dist = HashMap::with_capacity(network.nodes.len());

		let mut first_hop_targets = HashMap::with_capacity(if first_hops.is_some() { first_hops.as_ref().unwrap().len() } else { 0 });
		if let Some(hops) = first_hops {
			for chan in hops {
				let short_channel_id = chan.short_channel_id.expect("first_hops should be filled in with usable channels, not pending ones");
				if chan.remote_network_id == *target {
					return Ok(Route {
						hops: vec![RouteHop {
							pubkey: chan.remote_network_id,
							short_channel_id,
							fee_msat: final_value_msat,
							cltv_expiry_delta: final_cltv,
						}],
					});
				}
				first_hop_targets.insert(chan.remote_network_id, short_channel_id);
			}
			if first_hop_targets.is_empty() {
				return Err(HandleError{err: "Cannot route when there are no outbound routes away from us", action: None});
			}
		}

		macro_rules! add_entry {
			// Adds entry which goes from the node pointed to by $directional_info to
			// $dest_node_id over the channel with id $chan_id with fees described in
			// $directional_info.
			( $chan_id: expr, $dest_node_id: expr, $directional_info: expr, $starting_fee_msat: expr ) => {
				//TODO: Explore simply adding fee to hit htlc_minimum_msat
				if $starting_fee_msat as u64 + final_value_msat >= $directional_info.htlc_minimum_msat {
					let proportional_fee_millions = ($starting_fee_msat + final_value_msat).checked_mul($directional_info.fee_proportional_millionths as u64);
					if let Some(new_fee) = proportional_fee_millions.and_then(|part| {
							($directional_info.fee_base_msat as u64).checked_add(part / 1000000) })
					{
						let mut total_fee = $starting_fee_msat as u64;
						let hm_entry = dist.entry(&$directional_info.src_node_id);
						let old_entry = hm_entry.or_insert_with(|| {
							let node = network.nodes.get(&$directional_info.src_node_id).unwrap();
							(u64::max_value(),
								node.lowest_inbound_channel_fee_base_msat,
								node.lowest_inbound_channel_fee_proportional_millionths,
								RouteHop {
									pubkey: $dest_node_id.clone(),
									short_channel_id: 0,
									fee_msat: 0,
									cltv_expiry_delta: 0,
							})
						});
						if $directional_info.src_node_id != network.our_node_id {
							// Ignore new_fee for channel-from-us as we assume all channels-from-us
							// will have the same effective-fee
							total_fee += new_fee;
							if let Some(fee_inc) = final_value_msat.checked_add(total_fee).and_then(|inc| { (old_entry.2 as u64).checked_mul(inc) }) {
								total_fee += fee_inc / 1000000 + (old_entry.1 as u64);
							} else {
								// max_value means we'll always fail the old_entry.0 > total_fee check
								total_fee = u64::max_value();
							}
						}
						let new_graph_node = RouteGraphNode {
							pubkey: $directional_info.src_node_id,
							lowest_fee_to_peer_through_node: total_fee,
							lowest_fee_to_node: $starting_fee_msat as u64 + new_fee,
						};
						if old_entry.0 > total_fee {
							targets.push(new_graph_node);
							old_entry.0 = total_fee;
							old_entry.3 = RouteHop {
								pubkey: $dest_node_id.clone(),
								short_channel_id: $chan_id.clone(),
								fee_msat: new_fee, // This field is ignored on the last-hop anyway
								cltv_expiry_delta: $directional_info.cltv_expiry_delta as u32,
							}
						}
					}
				}
			};
		}

		macro_rules! add_entries_to_cheapest_to_target_node {
			( $node: expr, $node_id: expr, $fee_to_target_msat: expr ) => {
				if first_hops.is_some() {
					if let Some(first_hop) = first_hop_targets.get(&$node_id) {
						add_entry!(first_hop, $node_id, dummy_directional_info, $fee_to_target_msat);
					}
				}

				for chan_id in $node.channels.iter() {
					let chan = network.channels.get(chan_id).unwrap();
					if chan.one_to_two.src_node_id == *$node_id {
						// ie $node is one, ie next hop in A* is two, via the two_to_one channel
						if first_hops.is_none() || chan.two_to_one.src_node_id != network.our_node_id {
							if chan.two_to_one.enabled {
								add_entry!(chan_id, chan.one_to_two.src_node_id, chan.two_to_one, $fee_to_target_msat);
							}
						}
					} else {
						if first_hops.is_none() || chan.one_to_two.src_node_id != network.our_node_id {
							if chan.one_to_two.enabled {
								add_entry!(chan_id, chan.two_to_one.src_node_id, chan.one_to_two, $fee_to_target_msat);
							}
						}
					}
				}
			};
		}

		match network.nodes.get(target) {
			None => {},
			Some(node) => {
				add_entries_to_cheapest_to_target_node!(node, target, 0);
			},
		}

		for hop in last_hops.iter() {
			if first_hops.is_none() || hop.src_node_id != network.our_node_id { // first_hop overrules last_hops
				if network.nodes.get(&hop.src_node_id).is_some() {
					if first_hops.is_some() {
						if let Some(first_hop) = first_hop_targets.get(&hop.src_node_id) {
							add_entry!(first_hop, hop.src_node_id, dummy_directional_info, 0);
						}
					}
					add_entry!(hop.short_channel_id, target, hop, 0);
				}
			}
		}

		while let Some(RouteGraphNode { pubkey, lowest_fee_to_node, .. }) = targets.pop() {
			if pubkey == network.our_node_id {
				let mut res = vec!(dist.remove(&network.our_node_id).unwrap().3);
				while res.last().unwrap().pubkey != *target {
					let new_entry = match dist.remove(&res.last().unwrap().pubkey) {
						Some(hop) => hop.3,
						None => return Err(HandleError{err: "Failed to find a non-fee-overflowing path to the given destination", action: None}),
					};
					res.last_mut().unwrap().fee_msat = new_entry.fee_msat;
					res.last_mut().unwrap().cltv_expiry_delta = new_entry.cltv_expiry_delta;
					res.push(new_entry);
				}
				res.last_mut().unwrap().fee_msat = final_value_msat;
				res.last_mut().unwrap().cltv_expiry_delta = final_cltv;
				let route = Route { hops: res };
				log_trace!(self, "Got route: {}", log_route!(route));
				return Ok(route);
			}

			match network.nodes.get(&pubkey) {
				None => {},
				Some(node) => {
					add_entries_to_cheapest_to_target_node!(node, &pubkey, lowest_fee_to_node);
				},
			}
		}

		Err(HandleError{err: "Failed to find a path to the given destination", action: None})
	}
}

#[cfg(test)]
mod tests {
	use chain::chaininterface;
	use ln::channelmanager;
	use ln::router::{Router,NodeInfo,NetworkMap,ChannelInfo,DirectionalChannelInfo,RouteHint};
	use ln::msgs::GlobalFeatures;
	use util::test_utils;
	use util::test_utils::TestVecWriter;
	use util::logger::Logger;
	use util::ser::{Writeable, Readable};

	use bitcoin_hashes::sha256d::Hash as Sha256dHash;
	use bitcoin_hashes::Hash;
	use bitcoin::network::constants::Network;

	use hex;

	use secp256k1::key::{PublicKey,SecretKey};
	use secp256k1::Secp256k1;

	use std::sync::Arc;

	#[test]
	fn route_test() {
		let secp_ctx = Secp256k1::new();
		let our_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap());
		let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet, Arc::clone(&logger)));
		let router = Router::new(our_id, chain_monitor, Arc::clone(&logger));

		// Build network from our_id to node8:
		//
		//        -1(1)2-  node1  -1(3)2-
		//       /                       \
		// our_id -1(12)2- node8 -1(13)2--- node3
		//       \                       /
		//        -1(2)2-  node2  -1(4)2-
		//
		//
		// chan1  1-to-2: disabled
		// chan1  2-to-1: enabled, 0 fee
		//
		// chan2  1-to-2: enabled, ignored fee
		// chan2  2-to-1: enabled, 0 fee
		//
		// chan3  1-to-2: enabled, 0 fee
		// chan3  2-to-1: enabled, 100 msat fee
		//
		// chan4  1-to-2: enabled, 100% fee
		// chan4  2-to-1: enabled, 0 fee
		//
		// chan12 1-to-2: enabled, ignored fee
		// chan12 2-to-1: enabled, 0 fee
		//
		// chan13 1-to-2: enabled, 200% fee
		// chan13 2-to-1: enabled, 0 fee
		//
		//
		//       -1(5)2- node4 -1(8)2--
		//       |         2          |
		//       |       (11)         |
		//      /          1           \
		// node3--1(6)2- node5 -1(9)2--- node7 (not in global route map)
		//      \                      /
		//       -1(7)2- node6 -1(10)2-
		//
		// chan5  1-to-2: enabled, 100 msat fee
		// chan5  2-to-1: enabled, 0 fee
		//
		// chan6  1-to-2: enabled, 0 fee
		// chan6  2-to-1: enabled, 0 fee
		//
		// chan7  1-to-2: enabled, 100% fee
		// chan7  2-to-1: enabled, 0 fee
		//
		// chan8  1-to-2: enabled, variable fee (0 then 1000 msat)
		// chan8  2-to-1: enabled, 0 fee
		//
		// chan9  1-to-2: enabled, 1001 msat fee
		// chan9  2-to-1: enabled, 0 fee
		//
		// chan10 1-to-2: enabled, 0 fee
		// chan10 2-to-1: enabled, 0 fee
		//
		// chan11 1-to-2: enabled, 0 fee
		// chan11 2-to-1: enabled, 0 fee

		let node1 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()[..]).unwrap());
		let node2 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0303030303030303030303030303030303030303030303030303030303030303").unwrap()[..]).unwrap());
		let node3 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0404040404040404040404040404040404040404040404040404040404040404").unwrap()[..]).unwrap());
		let node4 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0505050505050505050505050505050505050505050505050505050505050505").unwrap()[..]).unwrap());
		let node5 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0606060606060606060606060606060606060606060606060606060606060606").unwrap()[..]).unwrap());
		let node6 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0707070707070707070707070707070707070707070707070707070707070707").unwrap()[..]).unwrap());
		let node7 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0808080808080808080808080808080808080808080808080808080808080808").unwrap()[..]).unwrap());
		let node8 = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0909090909090909090909090909090909090909090909090909090909090909").unwrap()[..]).unwrap());

		let zero_hash = Sha256dHash::hash(&[0; 32]);

		{
			let mut network = router.network_map.write().unwrap();

			network.nodes.insert(node1.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(1, zero_hash.clone()), NetworkMap::get_key(3, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 100,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(1, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: our_id.clone(),
					last_update: 0,
					enabled: false,
					cltv_expiry_delta: u16::max_value(), // This value should be ignored
					htlc_minimum_msat: 0,
					fee_base_msat: u32::max_value(), // This value should be ignored
					fee_proportional_millionths: u32::max_value(), // This value should be ignored
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node1.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: 0,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node2.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(2, zero_hash.clone()), NetworkMap::get_key(4, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(2, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: our_id.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: u16::max_value(), // This value should be ignored
					htlc_minimum_msat: 0,
					fee_base_msat: u32::max_value(), // This value should be ignored
					fee_proportional_millionths: u32::max_value(), // This value should be ignored
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node2.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: 0,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node8.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(12, zero_hash.clone()), NetworkMap::get_key(13, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(12, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: our_id.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: u16::max_value(), // This value should be ignored
					htlc_minimum_msat: 0,
					fee_base_msat: u32::max_value(), // This value should be ignored
					fee_proportional_millionths: u32::max_value(), // This value should be ignored
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node8.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: 0,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node3.clone(), NodeInfo {
				channels: vec!(
					NetworkMap::get_key(3, zero_hash.clone()),
					NetworkMap::get_key(4, zero_hash.clone()),
					NetworkMap::get_key(13, zero_hash.clone()),
					NetworkMap::get_key(5, zero_hash.clone()),
					NetworkMap::get_key(6, zero_hash.clone()),
					NetworkMap::get_key(7, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(3, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node1.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (3 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (3 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 100,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(4, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node2.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (4 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 1000000,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (4 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(13, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node8.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (13 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 2000000,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (13 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node4.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(5, zero_hash.clone()), NetworkMap::get_key(11, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(5, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (5 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 100,
					fee_proportional_millionths: 0,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node4.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (5 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node5.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(6, zero_hash.clone()), NetworkMap::get_key(11, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(6, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (6 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node5.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (6 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(11, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node5.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (11 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node4.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (11 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
			network.nodes.insert(node6.clone(), NodeInfo {
				channels: vec!(NetworkMap::get_key(7, zero_hash.clone())),
				lowest_inbound_channel_fee_base_msat: 0,
				lowest_inbound_channel_fee_proportional_millionths: 0,
				features: GlobalFeatures::new(),
				last_update: 1,
				rgb: [0; 3],
				alias: [0; 32],
				addresses: Vec::new(),
				announcement_message: None,
			});
			network.channels.insert(NetworkMap::get_key(7, zero_hash.clone()), ChannelInfo {
				features: GlobalFeatures::new(),
				one_to_two: DirectionalChannelInfo {
					src_node_id: node3.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (7 << 8) | 1,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 1000000,
					last_update_message: None,
				}, two_to_one: DirectionalChannelInfo {
					src_node_id: node6.clone(),
					last_update: 0,
					enabled: true,
					cltv_expiry_delta: (7 << 8) | 2,
					htlc_minimum_msat: 0,
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					last_update_message: None,
				},
				announcement_message: None,
			});
		}

		{ // Simple route to 3 via 2
			let route = router.get_route(&node3, None, &Vec::new(), 100, 42).unwrap();
			assert_eq!(route.hops.len(), 2);

			assert_eq!(route.hops[0].pubkey, node2);
			assert_eq!(route.hops[0].short_channel_id, 2);
			assert_eq!(route.hops[0].fee_msat, 100);
			assert_eq!(route.hops[0].cltv_expiry_delta, (4 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 4);
			assert_eq!(route.hops[1].fee_msat, 100);
			assert_eq!(route.hops[1].cltv_expiry_delta, 42);
		}

		{ // Route to 1 via 2 and 3 because our channel to 1 is disabled
			let route = router.get_route(&node1, None, &Vec::new(), 100, 42).unwrap();
			assert_eq!(route.hops.len(), 3);

			assert_eq!(route.hops[0].pubkey, node2);
			assert_eq!(route.hops[0].short_channel_id, 2);
			assert_eq!(route.hops[0].fee_msat, 200);
			assert_eq!(route.hops[0].cltv_expiry_delta, (4 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 4);
			assert_eq!(route.hops[1].fee_msat, 100);
			assert_eq!(route.hops[1].cltv_expiry_delta, (3 << 8) | 2);

			assert_eq!(route.hops[2].pubkey, node1);
			assert_eq!(route.hops[2].short_channel_id, 3);
			assert_eq!(route.hops[2].fee_msat, 100);
			assert_eq!(route.hops[2].cltv_expiry_delta, 42);
		}

		{ // If we specify a channel to node8, that overrides our local channel view and that gets used
			let our_chans = vec![channelmanager::ChannelDetails {
				channel_id: [0; 32],
				short_channel_id: Some(42),
				remote_network_id: node8.clone(),
				channel_value_satoshis: 0,
				user_id: 0,
				outbound_capacity_msat: 0,
				inbound_capacity_msat: 0,
				is_live: true,
			}];
			let route = router.get_route(&node3, Some(&our_chans), &Vec::new(), 100, 42).unwrap();
			assert_eq!(route.hops.len(), 2);

			assert_eq!(route.hops[0].pubkey, node8);
			assert_eq!(route.hops[0].short_channel_id, 42);
			assert_eq!(route.hops[0].fee_msat, 200);
			assert_eq!(route.hops[0].cltv_expiry_delta, (13 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 13);
			assert_eq!(route.hops[1].fee_msat, 100);
			assert_eq!(route.hops[1].cltv_expiry_delta, 42);
		}

		let mut last_hops = vec!(RouteHint {
				src_node_id: node4.clone(),
				short_channel_id: 8,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				cltv_expiry_delta: (8 << 8) | 1,
				htlc_minimum_msat: 0,
			}, RouteHint {
				src_node_id: node5.clone(),
				short_channel_id: 9,
				fee_base_msat: 1001,
				fee_proportional_millionths: 0,
				cltv_expiry_delta: (9 << 8) | 1,
				htlc_minimum_msat: 0,
			}, RouteHint {
				src_node_id: node6.clone(),
				short_channel_id: 10,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				cltv_expiry_delta: (10 << 8) | 1,
				htlc_minimum_msat: 0,
			});

		{ // Simple test across 2, 3, 5, and 4 via a last_hop channel
			let route = router.get_route(&node7, None, &last_hops, 100, 42).unwrap();
			assert_eq!(route.hops.len(), 5);

			assert_eq!(route.hops[0].pubkey, node2);
			assert_eq!(route.hops[0].short_channel_id, 2);
			assert_eq!(route.hops[0].fee_msat, 100);
			assert_eq!(route.hops[0].cltv_expiry_delta, (4 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 4);
			assert_eq!(route.hops[1].fee_msat, 0);
			assert_eq!(route.hops[1].cltv_expiry_delta, (6 << 8) | 1);

			assert_eq!(route.hops[2].pubkey, node5);
			assert_eq!(route.hops[2].short_channel_id, 6);
			assert_eq!(route.hops[2].fee_msat, 0);
			assert_eq!(route.hops[2].cltv_expiry_delta, (11 << 8) | 1);

			assert_eq!(route.hops[3].pubkey, node4);
			assert_eq!(route.hops[3].short_channel_id, 11);
			assert_eq!(route.hops[3].fee_msat, 0);
			assert_eq!(route.hops[3].cltv_expiry_delta, (8 << 8) | 1);

			assert_eq!(route.hops[4].pubkey, node7);
			assert_eq!(route.hops[4].short_channel_id, 8);
			assert_eq!(route.hops[4].fee_msat, 100);
			assert_eq!(route.hops[4].cltv_expiry_delta, 42);
		}

		{ // Simple test with outbound channel to 4 to test that last_hops and first_hops connect
			let our_chans = vec![channelmanager::ChannelDetails {
				channel_id: [0; 32],
				short_channel_id: Some(42),
				remote_network_id: node4.clone(),
				channel_value_satoshis: 0,
				user_id: 0,
				outbound_capacity_msat: 0,
				inbound_capacity_msat: 0,
				is_live: true,
			}];
			let route = router.get_route(&node7, Some(&our_chans), &last_hops, 100, 42).unwrap();
			assert_eq!(route.hops.len(), 2);

			assert_eq!(route.hops[0].pubkey, node4);
			assert_eq!(route.hops[0].short_channel_id, 42);
			assert_eq!(route.hops[0].fee_msat, 0);
			assert_eq!(route.hops[0].cltv_expiry_delta, (8 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node7);
			assert_eq!(route.hops[1].short_channel_id, 8);
			assert_eq!(route.hops[1].fee_msat, 100);
			assert_eq!(route.hops[1].cltv_expiry_delta, 42);
		}

		last_hops[0].fee_base_msat = 1000;

		{ // Revert to via 6 as the fee on 8 goes up
			let route = router.get_route(&node7, None, &last_hops, 100, 42).unwrap();
			assert_eq!(route.hops.len(), 4);

			assert_eq!(route.hops[0].pubkey, node2);
			assert_eq!(route.hops[0].short_channel_id, 2);
			assert_eq!(route.hops[0].fee_msat, 200); // fee increased as its % of value transferred across node
			assert_eq!(route.hops[0].cltv_expiry_delta, (4 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 4);
			assert_eq!(route.hops[1].fee_msat, 100);
			assert_eq!(route.hops[1].cltv_expiry_delta, (7 << 8) | 1);

			assert_eq!(route.hops[2].pubkey, node6);
			assert_eq!(route.hops[2].short_channel_id, 7);
			assert_eq!(route.hops[2].fee_msat, 0);
			assert_eq!(route.hops[2].cltv_expiry_delta, (10 << 8) | 1);

			assert_eq!(route.hops[3].pubkey, node7);
			assert_eq!(route.hops[3].short_channel_id, 10);
			assert_eq!(route.hops[3].fee_msat, 100);
			assert_eq!(route.hops[3].cltv_expiry_delta, 42);
		}

		{ // ...but still use 8 for larger payments as 6 has a variable feerate
			let route = router.get_route(&node7, None, &last_hops, 2000, 42).unwrap();
			assert_eq!(route.hops.len(), 5);

			assert_eq!(route.hops[0].pubkey, node2);
			assert_eq!(route.hops[0].short_channel_id, 2);
			assert_eq!(route.hops[0].fee_msat, 3000);
			assert_eq!(route.hops[0].cltv_expiry_delta, (4 << 8) | 1);

			assert_eq!(route.hops[1].pubkey, node3);
			assert_eq!(route.hops[1].short_channel_id, 4);
			assert_eq!(route.hops[1].fee_msat, 0);
			assert_eq!(route.hops[1].cltv_expiry_delta, (6 << 8) | 1);

			assert_eq!(route.hops[2].pubkey, node5);
			assert_eq!(route.hops[2].short_channel_id, 6);
			assert_eq!(route.hops[2].fee_msat, 0);
			assert_eq!(route.hops[2].cltv_expiry_delta, (11 << 8) | 1);

			assert_eq!(route.hops[3].pubkey, node4);
			assert_eq!(route.hops[3].short_channel_id, 11);
			assert_eq!(route.hops[3].fee_msat, 1000);
			assert_eq!(route.hops[3].cltv_expiry_delta, (8 << 8) | 1);

			assert_eq!(route.hops[4].pubkey, node7);
			assert_eq!(route.hops[4].short_channel_id, 8);
			assert_eq!(route.hops[4].fee_msat, 2000);
			assert_eq!(route.hops[4].cltv_expiry_delta, 42);
		}

		{ // Test Router serialization/deserialization
			let mut w = TestVecWriter(Vec::new());
			let network = router.network_map.read().unwrap();
			assert!(!network.channels.is_empty());
			assert!(!network.nodes.is_empty());
			network.write(&mut w).unwrap();
			assert!(<NetworkMap>::read(&mut ::std::io::Cursor::new(&w.0)).unwrap() == *network);
		}
	}
}
