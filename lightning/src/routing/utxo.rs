// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains traits for LDK to access UTXOs to check gossip data is correct.
//!
//! When lightning nodes gossip channel information, they resist DoS attacks by checking that each
//! channel matches a UTXO on-chain, requiring at least some marginal on-chain transacting in
//! order to announce a channel. This module handles that checking.

use bitcoin::amount::Amount;
use bitcoin::constants::ChainHash;
use bitcoin::TxOut;

use bitcoin::hex::DisplayHex;

use crate::events::MessageSendEvent;
use crate::ln::chan_utils::make_funding_redeemscript_from_slices;
use crate::ln::msgs::{self, ErrorAction, LightningError};
use crate::routing::gossip::{NetworkGraph, NodeId, P2PGossipSync};
use crate::util::logger::{Level, Logger};

use crate::prelude::*;

use crate::sync::{LockTestExt, Mutex};
use alloc::sync::{Arc, Weak};
use core::ops::Deref;

/// An error when accessing the chain via [`UtxoLookup`].
#[derive(Clone, Debug)]
pub enum UtxoLookupError {
	/// The requested chain is unknown.
	UnknownChain,

	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}

/// The result of a [`UtxoLookup::get_utxo`] call. A call may resolve either synchronously,
/// returning the `Sync` variant, or asynchronously, returning an [`UtxoFuture`] in the `Async`
/// variant.
#[derive(Clone)]
pub enum UtxoResult {
	/// A result which was resolved synchronously. It either includes a [`TxOut`] for the output
	/// requested or a [`UtxoLookupError`].
	Sync(Result<TxOut, UtxoLookupError>),
	/// A result which will be resolved asynchronously. It includes a [`UtxoFuture`], a `clone` of
	/// which you must keep locally and call [`UtxoFuture::resolve`] on once the lookup completes.
	///
	/// Note that in order to avoid runaway memory usage, the number of parallel checks is limited,
	/// but only fairly loosely. Because a pending checks block all message processing, leaving
	/// checks pending for an extended time may cause DoS of other functions. It is recommended you
	/// keep a tight timeout on lookups, on the order of a few seconds.
	Async(UtxoFuture),
}

/// The `UtxoLookup` trait defines behavior for accessing on-chain UTXOs.
pub trait UtxoLookup {
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `chain_hash` is for a different chain or if such a transaction output is
	/// unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(&self, chain_hash: &ChainHash, short_channel_id: u64) -> UtxoResult;
}

enum ChannelAnnouncement {
	Full(msgs::ChannelAnnouncement),
	Unsigned(msgs::UnsignedChannelAnnouncement),
}
impl ChannelAnnouncement {
	fn node_id_1(&self) -> &NodeId {
		match self {
			ChannelAnnouncement::Full(msg) => &msg.contents.node_id_1,
			ChannelAnnouncement::Unsigned(msg) => &msg.node_id_1,
		}
	}
}

enum NodeAnnouncement {
	Full(msgs::NodeAnnouncement),
	Unsigned(msgs::UnsignedNodeAnnouncement),
}
impl NodeAnnouncement {
	fn timestamp(&self) -> u32 {
		match self {
			NodeAnnouncement::Full(msg) => msg.contents.timestamp,
			NodeAnnouncement::Unsigned(msg) => msg.timestamp,
		}
	}
}

enum ChannelUpdate {
	Full(msgs::ChannelUpdate),
	Unsigned(msgs::UnsignedChannelUpdate),
}
impl ChannelUpdate {
	fn timestamp(&self) -> u32 {
		match self {
			ChannelUpdate::Full(msg) => msg.contents.timestamp,
			ChannelUpdate::Unsigned(msg) => msg.timestamp,
		}
	}
}

struct UtxoMessages {
	complete: Option<Result<TxOut, UtxoLookupError>>,
	channel_announce: Option<ChannelAnnouncement>,
	latest_node_announce_a: Option<NodeAnnouncement>,
	latest_node_announce_b: Option<NodeAnnouncement>,
	latest_channel_update_a: Option<ChannelUpdate>,
	latest_channel_update_b: Option<ChannelUpdate>,
}

/// Represents a future resolution of a [`UtxoLookup::get_utxo`] query resolving async.
///
/// See [`UtxoResult::Async`] and [`UtxoFuture::resolve`] for more info.
#[derive(Clone)]
pub struct UtxoFuture {
	state: Arc<Mutex<UtxoMessages>>,
}

/// A trivial implementation of [`UtxoLookup`] which is used to call back into the network graph
/// once we have a concrete resolution of a request.
pub(crate) struct UtxoResolver(Result<TxOut, UtxoLookupError>);
impl UtxoLookup for UtxoResolver {
	fn get_utxo(&self, _chain_hash: &ChainHash, _short_channel_id: u64) -> UtxoResult {
		UtxoResult::Sync(self.0.clone())
	}
}

impl UtxoFuture {
	/// Builds a new future for later resolution.
	pub fn new() -> Self {
		Self {
			state: Arc::new(Mutex::new(UtxoMessages {
				complete: None,
				channel_announce: None,
				latest_node_announce_a: None,
				latest_node_announce_b: None,
				latest_channel_update_a: None,
				latest_channel_update_b: None,
			})),
		}
	}

	/// Resolves this future against the given `graph` and with the given `result`.
	///
	/// This is identical to calling [`UtxoFuture::resolve`] with a dummy `gossip`, disabling
	/// forwarding the validated gossip message onwards to peers.
	///
	/// Because this may cause the [`NetworkGraph`]'s [`processing_queue_high`] to flip, in order
	/// to allow us to interact with peers again, you should call [`PeerManager::process_events`]
	/// after this.
	///
	/// [`processing_queue_high`]: crate::ln::msgs::RoutingMessageHandler::processing_queue_high
	/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
	pub fn resolve_without_forwarding<L: Deref>(
		&self, graph: &NetworkGraph<L>, result: Result<TxOut, UtxoLookupError>,
	) where
		L::Target: Logger,
	{
		self.do_resolve(graph, result);
	}

	/// Resolves this future against the given `graph` and with the given `result`.
	///
	/// The given `gossip` is used to broadcast any validated messages onwards to all peers which
	/// have available buffer space.
	///
	/// Because this may cause the [`NetworkGraph`]'s [`processing_queue_high`] to flip, in order
	/// to allow us to interact with peers again, you should call [`PeerManager::process_events`]
	/// after this.
	///
	/// [`processing_queue_high`]: crate::ln::msgs::RoutingMessageHandler::processing_queue_high
	/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
	pub fn resolve<
		L: Deref,
		G: Deref<Target = NetworkGraph<L>>,
		U: Deref,
		GS: Deref<Target = P2PGossipSync<G, U, L>>,
	>(
		&self, graph: &NetworkGraph<L>, gossip: GS, result: Result<TxOut, UtxoLookupError>,
	) where
		L::Target: Logger,
		U::Target: UtxoLookup,
	{
		let mut res = self.do_resolve(graph, result);
		for msg_opt in res.iter_mut() {
			if let Some(msg) = msg_opt.take() {
				gossip.forward_gossip_msg(msg);
			}
		}
	}

	fn do_resolve<L: Deref>(
		&self, graph: &NetworkGraph<L>, result: Result<TxOut, UtxoLookupError>,
	) -> [Option<MessageSendEvent>; 5]
	where
		L::Target: Logger,
	{
		let (announcement, node_a, node_b, update_a, update_b) = {
			let mut pending_checks = graph.pending_checks.internal.lock().unwrap();
			let mut async_messages = self.state.lock().unwrap();

			if async_messages.channel_announce.is_none() {
				// We raced returning to `check_channel_announcement` which hasn't updated
				// `channel_announce` yet. That's okay, we can set the `complete` field which it will
				// check once it gets control again.
				async_messages.complete = Some(result);
				return [None, None, None, None, None];
			}

			let announcement_msg = match async_messages.channel_announce.as_ref().unwrap() {
				ChannelAnnouncement::Full(signed_msg) => &signed_msg.contents,
				ChannelAnnouncement::Unsigned(msg) => &msg,
			};

			pending_checks.lookup_completed(announcement_msg, &Arc::downgrade(&self.state));

			(
				async_messages.channel_announce.take().unwrap(),
				async_messages.latest_node_announce_a.take(),
				async_messages.latest_node_announce_b.take(),
				async_messages.latest_channel_update_a.take(),
				async_messages.latest_channel_update_b.take(),
			)
		};

		let mut res = [None, None, None, None, None];
		let mut res_idx = 0;

		// Now that we've updated our internal state, pass the pending messages back through the
		// network graph with a different `UtxoLookup` which will resolve immediately.
		// Note that we ignore errors as we don't disconnect peers anyway, so there's nothing to do
		// with them.
		let resolver = UtxoResolver(result);
		match announcement {
			ChannelAnnouncement::Full(signed_msg) => {
				if graph.update_channel_from_announcement(&signed_msg, &Some(&resolver)).is_ok() {
					res[res_idx] = Some(MessageSendEvent::BroadcastChannelAnnouncement {
						msg: signed_msg,
						update_msg: None,
					});
					res_idx += 1;
				}
			},
			ChannelAnnouncement::Unsigned(msg) => {
				let _ = graph.update_channel_from_unsigned_announcement(&msg, &Some(&resolver));
			},
		}

		for announce in core::iter::once(node_a).chain(core::iter::once(node_b)) {
			match announce {
				Some(NodeAnnouncement::Full(signed_msg)) => {
					if graph.update_node_from_announcement(&signed_msg).is_ok() {
						res[res_idx] =
							Some(MessageSendEvent::BroadcastNodeAnnouncement { msg: signed_msg });
						res_idx += 1;
					}
				},
				Some(NodeAnnouncement::Unsigned(msg)) => {
					let _ = graph.update_node_from_unsigned_announcement(&msg);
				},
				None => {},
			}
		}

		for update in core::iter::once(update_a).chain(core::iter::once(update_b)) {
			match update {
				Some(ChannelUpdate::Full(signed_msg)) => {
					if graph.update_channel(&signed_msg).is_ok() {
						res[res_idx] =
							Some(MessageSendEvent::BroadcastChannelUpdate { msg: signed_msg });
						res_idx += 1;
					}
				},
				Some(ChannelUpdate::Unsigned(msg)) => {
					let _ = graph.update_channel_unsigned(&msg);
				},
				None => {},
			}
		}

		res
	}
}

struct PendingChecksContext {
	channels: HashMap<u64, Weak<Mutex<UtxoMessages>>>,
	nodes: HashMap<NodeId, Vec<Weak<Mutex<UtxoMessages>>>>,
}

impl PendingChecksContext {
	fn lookup_completed(
		&mut self, msg: &msgs::UnsignedChannelAnnouncement,
		completed_state: &Weak<Mutex<UtxoMessages>>,
	) {
		if let hash_map::Entry::Occupied(e) = self.channels.entry(msg.short_channel_id) {
			if Weak::ptr_eq(e.get(), &completed_state) {
				e.remove();
			}
		}

		if let hash_map::Entry::Occupied(mut e) = self.nodes.entry(msg.node_id_1) {
			e.get_mut().retain(|elem| !Weak::ptr_eq(&elem, &completed_state));
			if e.get().is_empty() {
				e.remove();
			}
		}
		if let hash_map::Entry::Occupied(mut e) = self.nodes.entry(msg.node_id_2) {
			e.get_mut().retain(|elem| !Weak::ptr_eq(&elem, &completed_state));
			if e.get().is_empty() {
				e.remove();
			}
		}
	}
}

/// A set of messages which are pending UTXO lookups for processing.
pub(super) struct PendingChecks {
	internal: Mutex<PendingChecksContext>,
}

impl PendingChecks {
	pub(super) fn new() -> Self {
		PendingChecks {
			internal: Mutex::new(PendingChecksContext {
				channels: new_hash_map(),
				nodes: new_hash_map(),
			}),
		}
	}

	/// Checks if there is a pending `channel_update` UTXO validation for the given channel,
	/// and, if so, stores the channel message for handling later and returns an `Err`.
	pub(super) fn check_hold_pending_channel_update(
		&self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>,
	) -> Result<(), LightningError> {
		let mut pending_checks = self.internal.lock().unwrap();
		if let hash_map::Entry::Occupied(e) = pending_checks.channels.entry(msg.short_channel_id) {
			let is_from_a = (msg.channel_flags & 1) == 1;
			match Weak::upgrade(e.get()) {
				Some(msgs_ref) => {
					let mut messages = msgs_ref.lock().unwrap();
					let latest_update = if is_from_a {
						&mut messages.latest_channel_update_a
					} else {
						&mut messages.latest_channel_update_b
					};
					if latest_update.is_none()
						|| latest_update.as_ref().unwrap().timestamp() < msg.timestamp
					{
						// If the messages we got has a higher timestamp, just blindly assume the
						// signatures on the new message are correct and drop the old message. This
						// may cause us to end up dropping valid `channel_update`s if a peer is
						// malicious, but we should get the correct ones when the node updates them.
						*latest_update = Some(if let Some(msg) = full_msg {
							ChannelUpdate::Full(msg.clone())
						} else {
							ChannelUpdate::Unsigned(msg.clone())
						});
					}
					return Err(LightningError {
						err: "Awaiting channel_announcement validation to accept channel_update"
							.to_owned(),
						action: ErrorAction::IgnoreAndLog(Level::Gossip),
					});
				},
				None => {
					e.remove();
				},
			}
		}
		Ok(())
	}

	/// Checks if there is a pending `node_announcement` UTXO validation for a channel with the
	/// given node and, if so, stores the channel message for handling later and returns an `Err`.
	pub(super) fn check_hold_pending_node_announcement(
		&self, msg: &msgs::UnsignedNodeAnnouncement, full_msg: Option<&msgs::NodeAnnouncement>,
	) -> Result<(), LightningError> {
		let mut pending_checks = self.internal.lock().unwrap();
		if let hash_map::Entry::Occupied(mut e) = pending_checks.nodes.entry(msg.node_id) {
			let mut found_at_least_one_chan = false;
			e.get_mut().retain(|node_msgs| match Weak::upgrade(&node_msgs) {
				Some(chan_mtx) => {
					let mut chan_msgs = chan_mtx.lock().unwrap();
					if let Some(chan_announce) = &chan_msgs.channel_announce {
						let latest_announce = if *chan_announce.node_id_1() == msg.node_id {
							&mut chan_msgs.latest_node_announce_a
						} else {
							&mut chan_msgs.latest_node_announce_b
						};
						if latest_announce.is_none()
							|| latest_announce.as_ref().unwrap().timestamp() < msg.timestamp
						{
							*latest_announce = Some(if let Some(msg) = full_msg {
								NodeAnnouncement::Full(msg.clone())
							} else {
								NodeAnnouncement::Unsigned(msg.clone())
							});
						}
						found_at_least_one_chan = true;
						true
					} else {
						debug_assert!(
							false,
							"channel_announce is set before struct is added to node map"
						);
						false
					}
				},
				None => false,
			});
			if e.get().is_empty() {
				e.remove();
			}
			if found_at_least_one_chan {
				return Err(LightningError {
					err: "Awaiting channel_announcement validation to accept node_announcement"
						.to_owned(),
					action: ErrorAction::IgnoreAndLog(Level::Gossip),
				});
			}
		}
		Ok(())
	}

	fn check_replace_previous_entry(
		msg: &msgs::UnsignedChannelAnnouncement, full_msg: Option<&msgs::ChannelAnnouncement>,
		replacement: Option<Weak<Mutex<UtxoMessages>>>,
		pending_channels: &mut HashMap<u64, Weak<Mutex<UtxoMessages>>>,
	) -> Result<(), msgs::LightningError> {
		match pending_channels.entry(msg.short_channel_id) {
			hash_map::Entry::Occupied(mut e) => {
				// There's already a pending lookup for the given SCID. Check if the messages
				// are the same and, if so, return immediately (don't bother spawning another
				// lookup if we haven't gotten that far yet).
				match Weak::upgrade(&e.get()) {
					Some(pending_msgs) => {
						// This may be called with the mutex held on a different UtxoMessages
						// struct, however in that case we have a global lockorder of new messages
						// -> old messages, which makes this safe.
						let pending_matches = match &pending_msgs
							.unsafe_well_ordered_double_lock_self()
							.channel_announce
						{
							Some(ChannelAnnouncement::Full(pending_msg)) => {
								Some(pending_msg) == full_msg
							},
							Some(ChannelAnnouncement::Unsigned(pending_msg)) => pending_msg == msg,
							None => {
								// This shouldn't actually be reachable. We set the
								// `channel_announce` field under the same lock as setting the
								// channel map entry. Still, we can just treat it as
								// non-matching and let the new request fly.
								debug_assert!(false);
								false
							},
						};
						if pending_matches {
							return Err(LightningError {
								err: "Channel announcement is already being checked".to_owned(),
								action: ErrorAction::IgnoreDuplicateGossip,
							});
						} else {
							// The earlier lookup is a different message. If we have another
							// request in-flight now replace the original.
							// Note that in the replace case whether to replace is somewhat
							// arbitrary - both results will be handled, we're just updating the
							// value that will be compared to future lookups with the same SCID.
							if let Some(item) = replacement {
								*e.get_mut() = item;
							}
						}
					},
					None => {
						// The earlier lookup already resolved. We can't be sure its the same
						// so just remove/replace it and move on.
						if let Some(item) = replacement {
							*e.get_mut() = item;
						} else {
							e.remove();
						}
					},
				}
			},
			hash_map::Entry::Vacant(v) => {
				if let Some(item) = replacement {
					v.insert(item);
				}
			},
		}
		Ok(())
	}

	pub(super) fn check_channel_announcement<U: Deref>(
		&self, utxo_lookup: &Option<U>, msg: &msgs::UnsignedChannelAnnouncement,
		full_msg: Option<&msgs::ChannelAnnouncement>,
	) -> Result<Option<Amount>, msgs::LightningError>
	where
		U::Target: UtxoLookup,
	{
		let handle_result = |res| match res {
			Ok(TxOut { value, script_pubkey }) => {
				let expected_script = make_funding_redeemscript_from_slices(
					msg.bitcoin_key_1.as_array(),
					msg.bitcoin_key_2.as_array(),
				)
				.to_p2wsh();
				if script_pubkey != expected_script {
					return Err(LightningError {
						err: format!(
							"Channel announcement key ({}) didn't match on-chain script ({})",
							expected_script.to_hex_string(),
							script_pubkey.to_hex_string()
						),
						action: ErrorAction::IgnoreError,
					});
				}
				Ok(Some(value))
			},
			Err(UtxoLookupError::UnknownChain) => Err(LightningError {
				err: format!(
					"Channel announced on an unknown chain ({})",
					msg.chain_hash.to_bytes().as_hex()
				),
				action: ErrorAction::IgnoreError,
			}),
			Err(UtxoLookupError::UnknownTx) => Err(LightningError {
				err: "Channel announced without corresponding UTXO entry".to_owned(),
				action: ErrorAction::IgnoreError,
			}),
		};

		Self::check_replace_previous_entry(
			msg,
			full_msg,
			None,
			&mut self.internal.lock().unwrap().channels,
		)?;

		match utxo_lookup {
			&None => {
				// Tentatively accept, potentially exposing us to DoS attacks
				Ok(None)
			},
			&Some(ref utxo_lookup) => {
				match utxo_lookup.get_utxo(&msg.chain_hash, msg.short_channel_id) {
					UtxoResult::Sync(res) => handle_result(res),
					UtxoResult::Async(future) => {
						let mut pending_checks = self.internal.lock().unwrap();
						let mut async_messages = future.state.lock().unwrap();
						if let Some(res) = async_messages.complete.take() {
							// In the unlikely event the future resolved before we managed to get it,
							// handle the result in-line.
							handle_result(res)
						} else {
							Self::check_replace_previous_entry(
								msg,
								full_msg,
								Some(Arc::downgrade(&future.state)),
								&mut pending_checks.channels,
							)?;
							async_messages.channel_announce = Some(if let Some(msg) = full_msg {
								ChannelAnnouncement::Full(msg.clone())
							} else {
								ChannelAnnouncement::Unsigned(msg.clone())
							});
							pending_checks
								.nodes
								.entry(msg.node_id_1)
								.or_default()
								.push(Arc::downgrade(&future.state));
							pending_checks
								.nodes
								.entry(msg.node_id_2)
								.or_default()
								.push(Arc::downgrade(&future.state));
							Err(LightningError {
								err: "Channel being checked async".to_owned(),
								action: ErrorAction::IgnoreAndLog(Level::Gossip),
							})
						}
					},
				}
			},
		}
	}

	/// The maximum number of pending gossip checks before [`Self::too_many_checks_pending`]
	/// returns `true`. Note that this isn't a strict upper-bound on the number of checks pending -
	/// each peer may, at a minimum, read one more socket buffer worth of `channel_announcement`s
	/// which we'll have to process. With a socket buffer of 4KB and a minimum
	/// `channel_announcement` size of, roughly, 429 bytes, this may leave us with `10*our peer
	/// count` messages to process beyond this limit. Because we'll probably have a few peers,
	/// there's no reason for this constant to be materially less than 30 or so, and 32 in-flight
	/// checks should be more than enough for decent parallelism.
	const MAX_PENDING_LOOKUPS: usize = 32;

	/// Returns true if there are a large number of async checks pending and future
	/// `channel_announcement` messages should be delayed. Note that this is only a hint and
	/// messages already in-flight may still have to be handled for various reasons.
	pub(super) fn too_many_checks_pending(&self) -> bool {
		let mut pending_checks = self.internal.lock().unwrap();
		if pending_checks.channels.len() > Self::MAX_PENDING_LOOKUPS {
			// If we have many channel checks pending, ensure we don't have any dangling checks
			// (i.e. checks where the user told us they'd call back but drop'd the `UtxoFuture`
			// instead) before we commit to applying backpressure.
			pending_checks.channels.retain(|_, chan| Weak::upgrade(&chan).is_some());
			pending_checks.nodes.retain(|_, channels| {
				channels.retain(|chan| Weak::upgrade(&chan).is_some());
				!channels.is_empty()
			});
			pending_checks.channels.len() > Self::MAX_PENDING_LOOKUPS
		} else {
			false
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::routing::gossip::tests::*;
	use crate::util::test_utils::{TestChainSource, TestLogger};

	use bitcoin::amount::Amount;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	use core::sync::atomic::Ordering;

	fn get_network() -> (TestChainSource, NetworkGraph<Box<TestLogger>>) {
		let logger = Box::new(TestLogger::new());
		let chain_source = TestChainSource::new(bitcoin::Network::Testnet);
		let network_graph = NetworkGraph::new(bitcoin::Network::Testnet, logger);

		(chain_source, network_graph)
	}

	fn get_test_objects() -> (
		msgs::ChannelAnnouncement,
		TestChainSource,
		NetworkGraph<Box<TestLogger>>,
		bitcoin::ScriptBuf,
		msgs::NodeAnnouncement,
		msgs::NodeAnnouncement,
		msgs::ChannelUpdate,
		msgs::ChannelUpdate,
		msgs::ChannelUpdate,
	) {
		let secp_ctx = Secp256k1::new();

		let (chain_source, network_graph) = get_network();

		let good_script = get_channel_script(&secp_ctx);
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let valid_announcement =
			get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);

		let node_a_announce = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
		let node_b_announce = get_signed_node_announcement(|_| {}, node_2_privkey, &secp_ctx);

		// Note that we have to set the "direction" flag correctly on both messages
		let chan_update_a =
			get_signed_channel_update(|msg| msg.channel_flags = 0, node_1_privkey, &secp_ctx);
		let chan_update_b =
			get_signed_channel_update(|msg| msg.channel_flags = 1, node_2_privkey, &secp_ctx);
		let chan_update_c = get_signed_channel_update(
			|msg| {
				msg.channel_flags = 1;
				msg.timestamp += 1;
			},
			node_2_privkey,
			&secp_ctx,
		);

		(
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			node_a_announce,
			node_b_announce,
			chan_update_a,
			chan_update_b,
			chan_update_c,
		)
	}

	#[test]
	fn test_fast_async_lookup() {
		// Check that async lookups which resolve quicker than the future is returned to the
		// `get_utxo` call can read it still resolve properly.
		let (valid_announcement, chain_source, network_graph, good_script, ..) = get_test_objects();

		let future = UtxoFuture::new();
		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }),
		);
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap();
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_some());
	}

	#[test]
	fn test_async_lookup() {
		// Test a simple async lookup
		let (
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			node_a_announce,
			node_b_announce,
			..,
		) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());

		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut { value: Amount::ZERO, script_pubkey: good_script }),
		);
		network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.unwrap();
		network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.unwrap();

		assert!(network_graph
			.read_only()
			.nodes()
			.get(&valid_announcement.contents.node_id_1)
			.unwrap()
			.announcement_info
			.is_none());

		network_graph.update_node_from_announcement(&node_a_announce).unwrap();
		network_graph.update_node_from_announcement(&node_b_announce).unwrap();

		assert!(network_graph
			.read_only()
			.nodes()
			.get(&valid_announcement.contents.node_id_1)
			.unwrap()
			.announcement_info
			.is_some());
	}

	#[test]
	fn test_invalid_async_lookup() {
		// Test an async lookup which returns an incorrect script
		let (valid_announcement, chain_source, network_graph, ..) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());

		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut {
				value: Amount::from_sat(1_000_000),
				script_pubkey: bitcoin::ScriptBuf::new(),
			}),
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());
	}

	#[test]
	fn test_failing_async_lookup() {
		// Test an async lookup which returns an error
		let (valid_announcement, chain_source, network_graph, ..) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());

		future.resolve_without_forwarding(&network_graph, Err(UtxoLookupError::UnknownTx));
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());
	}

	#[test]
	fn test_updates_async_lookup() {
		// Test async lookups will process pending channel_update/node_announcements once they
		// complete.
		let (
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			node_a_announce,
			node_b_announce,
			chan_update_a,
			chan_update_b,
			..,
		) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());

		assert_eq!(
			network_graph.update_node_from_announcement(&node_a_announce).unwrap_err().err,
			"Awaiting channel_announcement validation to accept node_announcement"
		);
		assert_eq!(
			network_graph.update_node_from_announcement(&node_b_announce).unwrap_err().err,
			"Awaiting channel_announcement validation to accept node_announcement"
		);

		assert_eq!(
			network_graph.update_channel(&chan_update_a).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);
		assert_eq!(
			network_graph.update_channel(&chan_update_b).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);

		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }),
		);

		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.unwrap()
			.one_to_two
			.is_some());
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.unwrap()
			.two_to_one
			.is_some());

		assert!(network_graph
			.read_only()
			.nodes()
			.get(&valid_announcement.contents.node_id_1)
			.unwrap()
			.announcement_info
			.is_some());
		assert!(network_graph
			.read_only()
			.nodes()
			.get(&valid_announcement.contents.node_id_2)
			.unwrap()
			.announcement_info
			.is_some());
	}

	#[test]
	fn test_latest_update_async_lookup() {
		// Test async lookups will process the latest channel_update if two are received while
		// awaiting an async UTXO lookup.
		let (
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			_,
			_,
			chan_update_a,
			chan_update_b,
			chan_update_c,
			..,
		) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.is_none());

		assert_eq!(
			network_graph.update_channel(&chan_update_a).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);
		assert_eq!(
			network_graph.update_channel(&chan_update_b).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);
		assert_eq!(
			network_graph.update_channel(&chan_update_c).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);

		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }),
		);

		assert_eq!(chan_update_a.contents.timestamp, chan_update_b.contents.timestamp);
		let graph_lock = network_graph.read_only();
		assert!(
			graph_lock
				.channels()
				.get(&valid_announcement.contents.short_channel_id)
				.as_ref()
				.unwrap()
				.one_to_two
				.as_ref()
				.unwrap()
				.last_update != graph_lock
				.channels()
				.get(&valid_announcement.contents.short_channel_id)
				.as_ref()
				.unwrap()
				.two_to_one
				.as_ref()
				.unwrap()
				.last_update
		);
	}

	#[test]
	fn test_no_double_lookups() {
		// Test that a pending async lookup will prevent a second async lookup from flying, but
		// only if the channel_announcement message is identical.
		let (valid_announcement, chain_source, network_graph, good_script, ..) = get_test_objects();

		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);

		// If we make a second request with the same message, the call count doesn't increase...
		let future_b = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future_b.clone());
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel announcement is already being checked"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);

		// But if we make a third request with a tweaked message, we should get a second call
		// against our new future...
		let secp_ctx = Secp256k1::new();
		let replacement_pk_1 = &SecretKey::from_slice(&[99; 32]).unwrap();
		let replacement_pk_2 = &SecretKey::from_slice(&[98; 32]).unwrap();
		let invalid_announcement =
			get_signed_channel_announcement(|_| {}, replacement_pk_1, replacement_pk_2, &secp_ctx);
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&invalid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 2);

		// Still, if we resolve the original future, the original channel will be accepted.
		future.resolve_without_forwarding(
			&network_graph,
			Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }),
		);
		assert!(!network_graph
			.read_only()
			.channels()
			.get(&valid_announcement.contents.short_channel_id)
			.unwrap()
			.announcement_message
			.as_ref()
			.unwrap()
			.contents
			.features
			.supports_unknown_test_feature());
	}

	#[test]
	fn test_checks_backpressure() {
		// Test that too_many_checks_pending returns true when there are many checks pending, and
		// returns false once they complete.
		let secp_ctx = Secp256k1::new();
		let (chain_source, network_graph) = get_network();

		// We cheat and use a single future for all the lookups to complete them all at once.
		let future = UtxoFuture::new();
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		for i in 0..PendingChecks::MAX_PENDING_LOOKUPS {
			let valid_announcement = get_signed_channel_announcement(
				|msg| msg.short_channel_id += 1 + i as u64,
				node_1_privkey,
				node_2_privkey,
				&secp_ctx,
			);
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err();
			assert!(!network_graph.pending_checks.too_many_checks_pending());
		}

		let valid_announcement =
			get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();
		assert!(network_graph.pending_checks.too_many_checks_pending());

		// Once the future completes the "too many checks" flag should reset.
		future.resolve_without_forwarding(&network_graph, Err(UtxoLookupError::UnknownTx));
		assert!(!network_graph.pending_checks.too_many_checks_pending());
	}

	#[test]
	fn test_checks_backpressure_drop() {
		// Test that too_many_checks_pending returns true when there are many checks pending, and
		// returns false if we drop some of the futures without completion.
		let secp_ctx = Secp256k1::new();
		let (chain_source, network_graph) = get_network();

		// We cheat and use a single future for all the lookups to complete them all at once.
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(UtxoFuture::new());

		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		for i in 0..PendingChecks::MAX_PENDING_LOOKUPS {
			let valid_announcement = get_signed_channel_announcement(
				|msg| msg.short_channel_id += 1 + i as u64,
				node_1_privkey,
				node_2_privkey,
				&secp_ctx,
			);
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err();
			assert!(!network_graph.pending_checks.too_many_checks_pending());
		}

		let valid_announcement =
			get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();
		assert!(network_graph.pending_checks.too_many_checks_pending());

		// Once the future is drop'd (by resetting the `utxo_ret` value) the "too many checks" flag
		// should reset to false.
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Err(UtxoLookupError::UnknownTx));
		assert!(!network_graph.pending_checks.too_many_checks_pending());
	}
}
