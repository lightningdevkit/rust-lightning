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

use crate::ln::chan_utils::make_funding_redeemscript_from_slices;
use crate::ln::msgs::{self, ErrorAction, LightningError, MessageSendEvent};
use crate::routing::gossip::{NetworkGraph, NodeId};
use crate::util::logger::{Level, Logger};
use crate::util::wakers::Notifier;

use crate::prelude::*;

use crate::sync::Mutex;
use alloc::sync::Arc;
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
	/// An `async_completion_notifier` is provided which should be [`Notifier::notify`]ed upon
	/// resolution of the [`UtxoFuture`] in case this method returns [`UtxoResult::Async`].
	///
	/// [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(
		&self, chain_hash: &ChainHash, short_channel_id: u64,
		async_completion_notifier: Arc<Notifier>,
	) -> UtxoResult;
}

impl<T: UtxoLookup + ?Sized, U: Deref<Target = T>> UtxoLookup for U {
	fn get_utxo(
		&self, chain_hash: &ChainHash, short_channel_id: u64,
		async_completion_notifier: Arc<Notifier>,
	) -> UtxoResult {
		self.deref().get_utxo(chain_hash, short_channel_id, async_completion_notifier)
	}
}

enum ChannelAnnouncement {
	Full(msgs::ChannelAnnouncement),
	Unsigned(msgs::UnsignedChannelAnnouncement),
}
impl ChannelAnnouncement {
	fn contents(&self) -> &msgs::UnsignedChannelAnnouncement {
		match self {
			ChannelAnnouncement::Full(msg) => &msg.contents,
			ChannelAnnouncement::Unsigned(msg) => msg,
		}
	}

	/// Returns true if the announcement is for a channel with the same node and bitcoin keys as
	/// `other`, i.e. both were produced by the same channel owners.
	fn same_keys(&self, other: &msgs::UnsignedChannelAnnouncement) -> bool {
		let contents = self.contents();
		contents.node_id_1 == other.node_id_1
			&& contents.node_id_2 == other.node_id_2
			&& contents.bitcoin_key_1 == other.bitcoin_key_1
			&& contents.bitcoin_key_2 == other.bitcoin_key_2
	}
}

#[derive(Clone)]
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

#[derive(PartialEq)]
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

struct UtxoFutureState {
	notifier: Arc<Notifier>,
	complete: Option<Result<TxOut, UtxoLookupError>>,
}

/// Represents a future resolution of a [`UtxoLookup::get_utxo`] query resolving async.
///
/// See [`UtxoResult::Async`] and [`UtxoFuture::resolve`] for more info.
#[derive(Clone)]
pub struct UtxoFuture {
	state: Arc<Mutex<UtxoFutureState>>,
}

/// A trivial implementation of [`UtxoLookup`] which is used to call back into the network graph
/// once we have a concrete resolution of a request.
pub(crate) struct UtxoResolver(Result<TxOut, UtxoLookupError>);
impl UtxoLookup for UtxoResolver {
	fn get_utxo(&self, _hash: &ChainHash, _scid: u64, _notifier: Arc<Notifier>) -> UtxoResult {
		UtxoResult::Sync(self.0.clone())
	}
}

impl UtxoFuture {
	/// Builds a new future for later resolution.
	pub fn new(notifier: Arc<Notifier>) -> Self {
		Self { state: Arc::new(Mutex::new(UtxoFutureState { notifier, complete: None })) }
	}

	/// Resolves this future with the given result.
	pub fn resolve(&self, result: Result<TxOut, UtxoLookupError>) {
		let mut state = self.state.lock().unwrap();
		state.complete = Some(result);
		state.notifier.notify();
	}
}

enum LookupState {
	Pending(UtxoFuture),
	/// The lookup has completed and the channel announcements are being added to the graph.
	/// Channel updates and node announcements in [`PendingLookup::updates`] and
	/// [`PendingChecksContext::nodes`] will be added once announcement processing completes.
	Resolved(Result<TxOut, UtxoLookupError>),
}

/// The messages queued behind the single UTXO lookup for one SCID.
struct PendingLookup {
	state: LookupState,
	/// The set of differently-keyed announcements, only one of which will be valid.
	announcements: Vec<ChannelAnnouncement>,
	/// The distinct `channel_update`s received for the SCID before its announcements were added to
	/// the graph. Their signatures are only checked once we know the single valid announcement.
	updates: Vec<ChannelUpdate>,
}

struct CompletedLookup {
	scid: u64,
	result: Result<TxOut, UtxoLookupError>,
	announcements: Vec<ChannelAnnouncement>,
}

struct PendingNode {
	/// The number of queued `channel_announcement`s which list this node.
	announcement_refs: usize,
	announcement: Option<NodeAnnouncement>,
}

struct PendingChecksContext {
	channels: HashMap<u64, PendingLookup>,
	nodes: HashMap<NodeId, PendingNode>,
}
impl PendingChecksContext {
	/// Returns the total number of gossip messages queued behind in-flight lookups.
	fn queued_messages(&self) -> usize {
		let channel_msgs: usize =
			self.channels.values().map(|l| l.announcements.len() + l.updates.len()).sum();
		let node_msgs = self.nodes.values().filter(|n| n.announcement.is_some()).count();
		channel_msgs + node_msgs
	}
}

pub(super) struct PendingChecks {
	internal: Mutex<PendingChecksContext>,
	pub(super) completion_notifier: Arc<Notifier>,
}

impl PendingChecks {
	pub(super) fn new() -> Self {
		PendingChecks {
			internal: Mutex::new(PendingChecksContext {
				channels: new_hash_map(),
				nodes: new_hash_map(),
			}),
			completion_notifier: Arc::new(Notifier::new()),
		}
	}

	/// Checks if there is a pending `channel_announcement` UTXO validation for the given channel,
	/// and, if so, stores the channel message for handling later and returns an `Err`.
	///
	/// Does NOT require that the `channel_update` be validated against the announcing node.
	pub(super) fn check_hold_pending_channel_update(
		&self, msg: &msgs::UnsignedChannelUpdate, full_msg: Option<&msgs::ChannelUpdate>,
	) -> Result<(), LightningError> {
		let mut pending_checks = self.internal.lock().unwrap();
		if let Some(lookup) = pending_checks.channels.get_mut(&msg.short_channel_id) {
			let update = if let Some(msg) = full_msg {
				ChannelUpdate::Full(msg.clone())
			} else {
				ChannelUpdate::Unsigned(msg.clone())
			};
			// We don't check sigs until we know which announcement to accept.
			if !lookup.updates.contains(&update) {
				lookup.updates.push(update);
			}
			return Err(LightningError {
				err: "Awaiting channel_announcement validation to accept channel_update".to_owned(),
				action: ErrorAction::IgnoreAndLog(Level::Gossip),
			});
		}
		Ok(())
	}

	/// Checks if there is a pending `channel_announcement` UTXO validation for a channel with the
	/// given node and, if so, stores the node message for handling later and returns an `Err`.
	///
	/// Requires that the provided announcement be authentically from the announcing node
	/// (either its signature has been validated or it comes from a trusted source).
	pub(super) fn check_hold_pending_node_announcement(
		&self, msg: &msgs::UnsignedNodeAnnouncement, full_msg: Option<&msgs::NodeAnnouncement>,
	) -> Result<(), LightningError> {
		let mut pending_checks = self.internal.lock().unwrap();
		if let Some(node) = pending_checks.nodes.get_mut(&msg.node_id) {
			let is_newer = node
				.announcement
				.as_ref()
				.map_or(true, |existing| existing.timestamp() < msg.timestamp);
			if is_newer {
				node.announcement = Some(if let Some(msg) = full_msg {
					NodeAnnouncement::Full(msg.clone())
				} else {
					NodeAnnouncement::Unsigned(msg.clone())
				});
			}
			return Err(LightningError {
				err: "Awaiting channel_announcement validation to accept node_announcement"
					.to_owned(),
				action: ErrorAction::IgnoreAndLog(Level::Gossip),
			});
		}
		Ok(())
	}

	fn queue_announcement(
		&self, lookup: &mut PendingLookup, nodes: &mut HashMap<NodeId, PendingNode>,
		msg: &msgs::UnsignedChannelAnnouncement, full_msg: Option<&msgs::ChannelAnnouncement>,
	) -> LightningError {
		if lookup.announcements.iter().any(|a| a.same_keys(msg)) {
			return LightningError {
				err: "Channel announcement is already being checked".to_owned(),
				action: ErrorAction::IgnoreDuplicateGossip,
			};
		}
		for node_id in [msg.node_id_1, msg.node_id_2] {
			nodes
				.entry(node_id)
				.or_insert(PendingNode { announcement_refs: 0, announcement: None })
				.announcement_refs += 1;
		}
		lookup.announcements.push(if let Some(msg) = full_msg {
			ChannelAnnouncement::Full(msg.clone())
		} else {
			ChannelAnnouncement::Unsigned(msg.clone())
		});
		LightningError {
			err: "Channel being checked async".to_owned(),
			action: ErrorAction::IgnoreAndLog(Level::Gossip),
		}
	}

	/// Validates or queues validation of a new `channel_announcement`.
	///
	/// Requires that the provided announcement be authentically from the public keys specified
	/// in the announcement (either the signatures have been validated or it comes from a
	/// trusted source).
	pub(super) fn check_channel_announcement<U: UtxoLookup>(
		&self, utxo_lookup: &Option<U>, msg: &msgs::UnsignedChannelAnnouncement,
		full_msg: Option<&msgs::ChannelAnnouncement>,
	) -> Result<Option<Amount>, msgs::LightningError> {
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

		let utxo_lookup = match utxo_lookup {
			&None => {
				// Tentatively accept, potentially exposing us to DoS attacks
				return Ok(None);
			},
			&Some(ref utxo_lookup) => utxo_lookup,
		};

		let mut pending_checks = self.internal.lock().unwrap();
		if !pending_checks.channels.contains_key(&msg.short_channel_id) {
			drop(pending_checks);
			let notifier = Arc::clone(&self.completion_notifier);
			let lookup_res = utxo_lookup.get_utxo(&msg.chain_hash, msg.short_channel_id, notifier);
			let future = match lookup_res {
				UtxoResult::Sync(res) => return handle_result(res),
				UtxoResult::Async(future) => future,
			};
			pending_checks = self.internal.lock().unwrap();
			let mut future_state = future.state.lock().unwrap();
			if let Some(res) = future_state.complete.take() {
				// In the unlikely event the future resolved before we managed to get it, handle
				// the result in-line.
				drop(future_state);
				drop(pending_checks);
				return handle_result(res);
			}
			drop(future_state);
			// If another thread started a lookup for the same SCID while ours was being created,
			// we use that one and drop our future.
			pending_checks.channels.entry(msg.short_channel_id).or_insert(PendingLookup {
				state: LookupState::Pending(future),
				announcements: Vec::new(),
				updates: Vec::new(),
			});
		}

		let PendingChecksContext { channels, nodes } = &mut *pending_checks;
		let lookup = channels.get_mut(&msg.short_channel_id).expect("Lookup was inserted above");
		match &lookup.state {
			LookupState::Pending(_) => Err(self.queue_announcement(lookup, nodes, msg, full_msg)),
			LookupState::Resolved(res) => handle_result(res.clone()),
		}
	}

	/// The maximum number of lookups in flight before [`Self::too_many_checks_pending`] returns
	/// `true`. Note that this isn't a strict upper-bound on the number of lookups pending - each
	/// peer may, at a minimum, read one more socket buffer worth of `channel_announcement`s which
	/// we'll have to process. With a socket buffer of 4KB and a minimum `channel_announcement`
	/// size of, roughly, 429 bytes, this may leave us with `10*our peer count` messages to process
	/// beyond this limit. Because we'll probably have a few peers, there's no reason for this
	/// constant to be materially less than 30 or so, and 32 in-flight checks should be more than
	/// enough for decent parallelism.
	const MAX_PENDING_LOOKUPS: usize = 32;

	/// The maximum number of gossip messages queued behind in-flight lookups before
	/// [`Self::too_many_checks_pending`] returns `true`. As with [`Self::MAX_PENDING_LOOKUPS`]
	/// this is not a strict bound but only impacts queued messages rather than lookups.
	const MAX_PENDING_MESSAGES: usize = 128;

	/// Returns true if there are a large number of async checks pending, or messages queued behind
	/// them, and future gossip messages should be delayed. Note that this is only a hint and
	/// messages already in-flight may still have to be handled for various reasons.
	pub(super) fn too_many_checks_pending(&self) -> bool {
		let pending_checks = self.internal.lock().unwrap();
		pending_checks.channels.len() > Self::MAX_PENDING_LOOKUPS
			|| pending_checks.queued_messages() > Self::MAX_PENDING_MESSAGES
	}

	/// Releases the references the given queued announcements hold on their nodes, returning a copy
	/// of any `node_announcement` held for those nodes so that it can be applied if a channel for
	/// the node is accepted.
	fn release_node_refs(
		nodes: &mut HashMap<NodeId, PendingNode>, announcements: &[ChannelAnnouncement],
	) -> Vec<NodeAnnouncement> {
		let mut node_announcements = Vec::new();
		for chan_announcement in announcements.iter() {
			let contents = chan_announcement.contents();
			for node_id in [contents.node_id_1, contents.node_id_2] {
				let mut entry = match nodes.entry(node_id) {
					hash_map::Entry::Occupied(entry) => entry,
					hash_map::Entry::Vacant(_) => {
						debug_assert!(false, "Queued announcements reference their nodes");
						continue;
					},
				};
				entry.get_mut().announcement_refs -= 1;
				let node_announcement = if entry.get().announcement_refs == 0 {
					entry.remove().announcement
				} else {
					entry.get().announcement.clone()
				};
				if let Some(announcement) = node_announcement {
					node_announcements.push(announcement);
				}
			}
		}
		node_announcements
	}

	/// Moves lookups whose futures have completed to [`LookupState::Resolved`], returning their
	/// results and queued announcements. Lookups whose futures were dropped are removed along with
	/// any messages queued behind them.
	fn take_completed_lookups(&self) -> Vec<CompletedLookup> {
		let mut completed_lookups = Vec::new();
		let mut pending_checks = self.internal.lock().unwrap();
		let PendingChecksContext { channels, nodes } = &mut *pending_checks;
		channels.retain(|scid, lookup| {
			let future = match &lookup.state {
				LookupState::Pending(future) => future,
				LookupState::Resolved(_) => return true,
			};
			let mut state_lock = future.state.lock().unwrap();
			if let Some(result) = state_lock.complete.take() {
				drop(state_lock);
				completed_lookups.push(CompletedLookup {
					scid: *scid,
					result: result.clone(),
					announcements: core::mem::take(&mut lookup.announcements),
				});
				lookup.state = LookupState::Resolved(result);
				true
			} else if Arc::strong_count(&future.state) == 1 {
				// If the downstream code has dropped the future, whatever the current result is
				// isn't going to change.
				drop(state_lock);
				Self::release_node_refs(nodes, &lookup.announcements);
				false
			} else {
				true
			}
		});
		completed_lookups
	}

	/// Adds the announcements of the given completed lookups to the graph, then removes the lookups
	/// and applies the other messages queued behind them.
	fn apply_completed_lookups<L: Logger>(
		&self, graph: &NetworkGraph<L>, completed_lookups: Vec<CompletedLookup>,
	) -> Vec<MessageSendEvent> {
		let mut new_messages = Vec::with_capacity(completed_lookups.len() * 5);

		// Pass the pending messages back through the network graph with a different `UtxoLookup`
		// which will resolve immediately.
		// Note that we ignore errors as we don't disconnect peers anyway, so there's nothing to do
		// with them.
		for lookup in completed_lookups.iter() {
			let resolver = UtxoResolver(lookup.result.clone());
			for announcement in lookup.announcements.iter() {
				match announcement {
					ChannelAnnouncement::Full(signed_msg) => {
						if graph
							.update_channel_from_announcement(signed_msg, &Some(&resolver))
							.is_ok()
						{
							new_messages.push(MessageSendEvent::BroadcastChannelAnnouncement {
								msg: signed_msg.clone(),
								update_msg: None,
							});
						}
					},
					ChannelAnnouncement::Unsigned(msg) => {
						let _ =
							graph.update_channel_from_unsigned_announcement(msg, &Some(&resolver));
					},
				}
			}
		}

		// Only once the announcements have been added to the graph can we remove the lookups, as
		// until then messages for their channels and nodes must continue to be queued.
		let mut node_announcements = Vec::new();
		let mut updates = Vec::new();
		{
			let mut pending_checks = self.internal.lock().unwrap();
			let PendingChecksContext { channels, nodes } = &mut *pending_checks;
			for completed in completed_lookups {
				let lookup = match channels.remove(&completed.scid) {
					Some(lookup) => lookup,
					None => {
						debug_assert!(false, "Resolved lookups are only removed here");
						continue;
					},
				};
				debug_assert!(matches!(lookup.state, LookupState::Resolved(_)));
				debug_assert!(lookup.announcements.is_empty());
				let released = Self::release_node_refs(nodes, &completed.announcements);
				node_announcements.extend(released);
				updates.extend(lookup.updates);
			}
		}

		for announce in node_announcements {
			match announce {
				NodeAnnouncement::Full(signed_msg) => {
					if graph.update_node_from_announcement(&signed_msg).is_ok() {
						new_messages
							.push(MessageSendEvent::BroadcastNodeAnnouncement { msg: signed_msg });
					}
				},
				NodeAnnouncement::Unsigned(msg) => {
					let _ = graph.update_node_from_unsigned_announcement(&msg);
				},
			}
		}

		// Apply the newest update first so that older ones are trivially rejected.
		updates.sort_by(|a, b| b.timestamp().cmp(&a.timestamp()));
		for update in updates {
			match update {
				ChannelUpdate::Full(signed_msg) => {
					if let Ok(Some((node_id_1, node_id_2))) = graph.update_channel(&signed_msg) {
						new_messages.push(MessageSendEvent::BroadcastChannelUpdate {
							msg: signed_msg,
							node_id_1,
							node_id_2,
						});
					}
				},
				ChannelUpdate::Unsigned(msg) => {
					let _ = graph.update_channel_unsigned(&msg);
				},
			}
		}
		new_messages
	}

	pub(super) fn check_resolved_futures<L: Logger>(
		&self, graph: &NetworkGraph<L>,
	) -> Vec<MessageSendEvent> {
		let completed_lookups = self.take_completed_lookups();
		self.apply_completed_lookups(graph, completed_lookups)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::routing::gossip::tests::*;
	use crate::routing::test_utils::channel_announcement;
	use crate::types::features::ChannelFeatures;
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

		(
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			node_a_announce,
			node_b_announce,
			get_signed_channel_update(|msg| msg.channel_flags = 0, node_1_privkey, &secp_ctx),
			get_signed_channel_update(|msg| msg.channel_flags = 1, node_2_privkey, &secp_ctx),
			// Note that we have to set the "direction" flag correctly on both messages
			get_signed_channel_update(
				|msg| {
					msg.channel_flags = 1;
					msg.timestamp += 1;
				},
				node_2_privkey,
				&secp_ctx,
			),
		)
	}

	/// Builds a correctly-signed announcement for the given SCID whose bitcoin keys will not match
	/// the output returned for `get_test_objects`' announcement.
	fn get_mismatched_announcement(scid: u64) -> msgs::ChannelAnnouncement {
		let secp_ctx = Secp256k1::new();
		channel_announcement(
			&SecretKey::from_slice(&[99; 32]).unwrap(),
			&SecretKey::from_slice(&[98; 32]).unwrap(),
			ChannelFeatures::empty(),
			scid,
			&secp_ctx,
		)
	}

	fn pending_message_count(network_graph: &NetworkGraph<Box<TestLogger>>) -> usize {
		network_graph.pending_checks.internal.lock().unwrap().queued_messages()
	}

	fn pending_lookup_count(network_graph: &NetworkGraph<Box<TestLogger>>) -> usize {
		network_graph.pending_checks.internal.lock().unwrap().channels.len()
	}

	#[test]
	fn test_fast_async_lookup() {
		// Check that async lookups which resolve quicker than the future is returned to the
		// `get_utxo` call can read it still resolve properly.
		let (valid_announcement, chain_source, network_graph, good_script, ..) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		assert!(notifier.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap();
		assert!(network_graph.read_only().channels().get(&scid).is_some());
		assert_eq!(pending_message_count(&network_graph), 0);
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
		let scid = valid_announcement.contents.short_channel_id;
		let node_id_1 = valid_announcement.contents.node_id_1;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph.read_only().channels().get(&scid).is_none());
		assert_eq!(pending_message_count(&network_graph), 1);

		future.resolve(Ok(TxOut { value: Amount::ZERO, script_pubkey: good_script }));
		assert!(notifier.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		network_graph.read_only().channels().get(&scid).unwrap();
		network_graph.read_only().channels().get(&scid).unwrap();
		assert_eq!(pending_message_count(&network_graph), 0);

		#[rustfmt::skip]
		let is_node_a_announced = network_graph.read_only().nodes().get(&node_id_1).unwrap()
			.announcement_info.is_some();
		assert!(!is_node_a_announced);

		network_graph.update_node_from_announcement(&node_a_announce).unwrap();
		network_graph.update_node_from_announcement(&node_b_announce).unwrap();

		#[rustfmt::skip]
		let is_node_a_announced = network_graph.read_only().nodes().get(&node_id_1).unwrap()
			.announcement_info.is_some();
		assert!(is_node_a_announced);
	}

	#[test]
	fn test_invalid_async_lookup() {
		// Test an async lookup which returns an incorrect script
		let (valid_announcement, chain_source, network_graph, ..) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph.read_only().channels().get(&scid).is_none());

		let value = Amount::from_sat(1_000_000);
		future.resolve(Ok(TxOut { value, script_pubkey: bitcoin::ScriptBuf::new() }));
		assert!(notifier.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(network_graph.read_only().channels().get(&scid).is_none());
		assert_eq!(pending_message_count(&network_graph), 0);
	}

	#[test]
	fn test_failing_async_lookup() {
		// Test an async lookup which returns an error
		let (valid_announcement, chain_source, network_graph, ..) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph.read_only().channels().get(&scid).is_none());

		future.resolve(Err(UtxoLookupError::UnknownTx));
		assert!(notifier.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(network_graph.read_only().channels().get(&scid).is_none());
		assert_eq!(pending_message_count(&network_graph), 0);
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
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph.read_only().channels().get(&scid).is_none());

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
		assert_eq!(pending_message_count(&network_graph), 5);

		assert!(!notifier.notify_pending());
		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		assert!(notifier.notify_pending());
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert_eq!(msgs.len(), 5);
		assert_eq!(pending_message_count(&network_graph), 0);

		assert!(network_graph.read_only().channels().get(&scid).unwrap().one_to_two.is_some());
		assert!(network_graph.read_only().channels().get(&scid).unwrap().two_to_one.is_some());

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
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert!(network_graph.read_only().channels().get(&scid).is_none());

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

		assert!(!notifier.notify_pending());
		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		assert!(notifier.notify_pending());
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		// Only the newest update in each direction is applied and broadcast.
		let update_broadcasts = msgs
			.iter()
			.filter(|msg| matches!(msg, MessageSendEvent::BroadcastChannelUpdate { .. }))
			.count();
		assert_eq!(update_broadcasts, 2);

		assert_eq!(chan_update_a.contents.timestamp, chan_update_b.contents.timestamp);
		let graph_lock = network_graph.read_only();
		#[rustfmt::skip]
		let one_to_two_update =
			graph_lock.channels().get(&scid).as_ref().unwrap().one_to_two.as_ref().unwrap().last_update;
		#[rustfmt::skip]
		let two_to_one_update =
			graph_lock.channels().get(&scid).as_ref().unwrap().two_to_one.as_ref().unwrap().last_update;
		assert_eq!(one_to_two_update, chan_update_a.contents.timestamp);
		assert_eq!(two_to_one_update, chan_update_c.contents.timestamp);
	}

	#[test]
	fn test_bogus_update_does_not_displace_valid_update() {
		// While a channel is pending validation we cannot check update signatures, so an update
		// with a higher timestamp must not cause a valid one to be dropped.
		let (valid_announcement, chain_source, network_graph, good_script, _, _, chan_update_a, ..) =
			get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();

		let secp_ctx = Secp256k1::new();
		let bogus_key = &SecretKey::from_slice(&[99; 32]).unwrap();
		let bogus_update = get_signed_channel_update(
			|msg| {
				msg.channel_flags = 0;
				msg.timestamp = chan_update_a.contents.timestamp + 1;
			},
			bogus_key,
			&secp_ctx,
		);
		network_graph.update_channel(&bogus_update).unwrap_err();
		network_graph.update_channel(&chan_update_a).unwrap_err();
		// Resending an update does not queue it again.
		network_graph.update_channel(&chan_update_a).unwrap_err();
		assert_eq!(pending_message_count(&network_graph), 3);

		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		let update_broadcasts = msgs
			.iter()
			.filter(|msg| matches!(msg, MessageSendEvent::BroadcastChannelUpdate { .. }))
			.count();
		assert_eq!(update_broadcasts, 1);
		assert_eq!(pending_message_count(&network_graph), 0);

		let graph_lock = network_graph.read_only();
		let channel = graph_lock.channels().get(&scid).unwrap();
		assert_eq!(
			channel.one_to_two.as_ref().unwrap().last_update,
			chan_update_a.contents.timestamp
		);
	}

	#[test]
	fn test_no_double_lookups() {
		// Test that a pending async lookup will prevent a second lookup for the same SCID, with
		// identical announcements ignored and differing ones queued on the existing lookup.
		let (valid_announcement, chain_source, network_graph, good_script, ..) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier_a = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier_a));
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
		let notifier_b = Arc::new(Notifier::new());
		let future_b = UtxoFuture::new(Arc::clone(&notifier_b));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future_b.clone());
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel announcement is already being checked"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);

		// ...nor does it if we make a third request with a different message, which is instead
		// queued on the existing lookup.
		let mismatched_announcement = get_mismatched_announcement(scid);
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&mismatched_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);
		assert_eq!(pending_message_count(&network_graph), 2);

		// Once we resolve the original future, the original channel will be accepted.
		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		assert!(notifier_a.notify_pending());
		assert!(!notifier_b.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		let graph_lock = network_graph.read_only();
		let channel = graph_lock.channels().get(&scid).unwrap();
		assert_eq!(channel.node_one, valid_announcement.contents.node_id_1);
		assert_eq!(channel.node_two, valid_announcement.contents.node_id_2);
		assert!(graph_lock.nodes().get(&mismatched_announcement.contents.node_id_1).is_none());
		assert_eq!(pending_message_count(&network_graph), 0);
	}

	#[test]
	fn test_mismatched_announcement_first() {
		// A correctly-signed announcement for the same SCID whose keys don't match the on-chain
		// output must not prevent a later valid announcement, or the messages queued behind it,
		// from being accepted.
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
		let scid = valid_announcement.contents.short_channel_id;
		let mismatched_announcement = get_mismatched_announcement(scid);

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		assert_eq!(
			network_graph
				.update_channel_from_announcement(&mismatched_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel being checked async"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);

		network_graph.update_node_from_announcement(&node_a_announce).unwrap_err();
		network_graph.update_node_from_announcement(&node_b_announce).unwrap_err();
		network_graph.update_channel(&chan_update_a).unwrap_err();
		network_graph.update_channel(&chan_update_b).unwrap_err();
		assert_eq!(pending_message_count(&network_graph), 6);

		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert_eq!(msgs.len(), 5);
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().nodes.is_empty());

		let graph_lock = network_graph.read_only();
		let channel = graph_lock.channels().get(&scid).unwrap();
		assert_eq!(channel.node_one, valid_announcement.contents.node_id_1);
		assert_eq!(channel.node_two, valid_announcement.contents.node_id_2);
		assert!(channel.one_to_two.is_some());
		assert!(channel.two_to_one.is_some());
		for node_id in
			[valid_announcement.contents.node_id_1, valid_announcement.contents.node_id_2]
		{
			assert!(graph_lock.nodes().get(&node_id).unwrap().announcement_info.is_some());
		}
		assert!(graph_lock.nodes().get(&mismatched_announcement.contents.node_id_1).is_none());
		assert!(graph_lock.nodes().get(&mismatched_announcement.contents.node_id_2).is_none());
	}

	#[test]
	fn test_same_keys_announcement_ignored() {
		// A differing announcement signed by the same keys as a pending one is treated as a
		// duplicate rather than being queued alongside it.
		let (valid_announcement, chain_source, network_graph, good_script, ..) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();

		let secp_ctx = Secp256k1::new();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		let differing_announcement = get_signed_channel_announcement(
			|msg| msg.excess_data.push(42),
			node_1_privkey,
			node_2_privkey,
			&secp_ctx,
		);
		assert_eq!(
			network_graph
				.update_channel_from_announcement(&differing_announcement, &Some(&chain_source))
				.unwrap_err()
				.err,
			"Channel announcement is already being checked"
		);
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);
		assert_eq!(pending_message_count(&network_graph), 1);

		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert_eq!(msgs.len(), 1);
		let graph_lock = network_graph.read_only();
		let channel = graph_lock.channels().get(&scid).unwrap();
		let announcement = channel.announcement_message.as_ref().unwrap();
		assert!(announcement.contents.excess_data.is_empty());
	}

	#[test]
	fn test_node_announcement_held_across_lookups() {
		// A node_announcement for a node with several pending channels must be applied once any
		// of them is accepted, even if another of them fails first.
		let (valid_announcement, chain_source, network_graph, good_script, node_a_announce, ..) =
			get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;
		let node_a_id = node_a_announce.contents.node_id;

		let secp_ctx = Secp256k1::new();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_3_privkey = &SecretKey::from_slice(&[43; 32]).unwrap();
		let second_announcement = get_signed_channel_announcement(
			|msg| msg.short_channel_id = scid + 1,
			node_1_privkey,
			node_3_privkey,
			&secp_ctx,
		);

		let notifier = Arc::new(Notifier::new());
		let future_1 = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future_1.clone());
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();
		let future_2 = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future_2.clone());
		network_graph
			.update_channel_from_announcement(&second_announcement, &Some(&chain_source))
			.unwrap_err();
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 2);

		assert_eq!(
			network_graph.update_node_from_announcement(&node_a_announce).unwrap_err().err,
			"Awaiting channel_announcement validation to accept node_announcement"
		);
		assert_eq!(pending_message_count(&network_graph), 3);

		// The second channel failing validation releases its node references but keeps the
		// node_announcement around for the first.
		future_2.resolve(Err(UtxoLookupError::UnknownTx));
		assert!(network_graph.pending_checks.check_resolved_futures(&network_graph).is_empty());
		assert!(network_graph.read_only().channels().get(&(scid + 1)).is_none());
		assert_eq!(pending_message_count(&network_graph), 2);
		{
			let pending_checks = network_graph.pending_checks.internal.lock().unwrap();
			assert_eq!(pending_checks.nodes.len(), 2);
			assert!(pending_checks.nodes.get(&node_a_id).unwrap().announcement.is_some());
		}

		future_1
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		let msgs = network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert_eq!(msgs.len(), 2);
		assert!(msgs
			.iter()
			.any(|msg| matches!(msg, MessageSendEvent::BroadcastNodeAnnouncement { .. })));
		assert!(network_graph
			.read_only()
			.nodes()
			.get(&node_a_id)
			.unwrap()
			.announcement_info
			.is_some());
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().nodes.is_empty());
	}

	#[test]
	fn test_messages_queued_while_applying_completed_lookup() {
		// Messages which arrive after a lookup completes but before its announcement has been
		// added to the graph must still be queued and applied rather than rejected.
		let (
			valid_announcement,
			chain_source,
			network_graph,
			good_script,
			node_a_announce,
			_,
			chan_update_a,
			..,
		) = get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;
		let node_a_id = node_a_announce.contents.node_id;

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();

		future
			.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: good_script }));
		let completed_lookups = network_graph.pending_checks.take_completed_lookups();
		assert_eq!(completed_lookups.len(), 1);
		assert!(network_graph.read_only().channels().get(&scid).is_none());

		assert_eq!(
			network_graph.update_channel(&chan_update_a).unwrap_err().err,
			"Awaiting channel_announcement validation to accept channel_update"
		);
		assert_eq!(
			network_graph.update_node_from_announcement(&node_a_announce).unwrap_err().err,
			"Awaiting channel_announcement validation to accept node_announcement"
		);

		// Further announcements for the SCID are checked against the completed lookup's result
		// rather than starting a new lookup.
		let mismatched_announcement = get_mismatched_announcement(scid);
		let err = network_graph
			.update_channel_from_announcement(&mismatched_announcement, &Some(&chain_source))
			.unwrap_err();
		assert!(err.err.contains("didn't match on-chain script"));
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);

		let msgs =
			network_graph.pending_checks.apply_completed_lookups(&network_graph, completed_lookups);
		assert_eq!(msgs.len(), 3);
		assert_eq!(pending_lookup_count(&network_graph), 0);
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().nodes.is_empty());

		let graph_lock = network_graph.read_only();
		let channel = graph_lock.channels().get(&scid).unwrap();
		assert_eq!(channel.node_one, valid_announcement.contents.node_id_1);
		assert!(channel.one_to_two.is_some());
		assert!(graph_lock.nodes().get(&node_a_id).unwrap().announcement_info.is_some());
	}

	#[test]
	fn test_dropped_future_discards_queued_messages() {
		// If the user drops a future without resolving it, everything queued behind it is dropped
		// and a later announcement starts a fresh lookup.
		let (valid_announcement, chain_source, network_graph, good_script, _, _, chan_update_a, ..) =
			get_test_objects();
		let scid = valid_announcement.contents.short_channel_id;

		let notifier = Arc::new(Notifier::new());
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(UtxoFuture::new(notifier));
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();
		network_graph.update_channel(&chan_update_a).unwrap_err();
		assert_eq!(pending_message_count(&network_graph), 2);

		// Replacing the value the chain source hands out drops the only remaining reference to
		// the future outside of the pending lookup.
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Ok(TxOut {
			value: Amount::from_sat(1_000_000),
			script_pubkey: good_script,
		}));
		assert!(network_graph.pending_checks.check_resolved_futures(&network_graph).is_empty());
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().nodes.is_empty());
		assert!(network_graph.read_only().channels().get(&scid).is_none());

		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap();
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 2);
		let graph_lock = network_graph.read_only();
		assert!(graph_lock.channels().get(&scid).unwrap().one_to_two.is_none());
	}

	#[test]
	fn test_checks_backpressure() {
		// Test that too_many_checks_pending returns true when there are many checks pending, and
		// returns false once they complete.
		let secp_ctx = Secp256k1::new();
		let (chain_source, network_graph) = get_network();

		let notifier = Arc::new(Notifier::new());
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let mut futures = Vec::new();
		for i in 0..=PendingChecks::MAX_PENDING_LOOKUPS {
			let future = UtxoFuture::new(Arc::clone(&notifier));
			*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
			futures.push(future);
			let valid_announcement = get_signed_channel_announcement(
				|msg| msg.short_channel_id += i as u64,
				node_1_privkey,
				node_2_privkey,
				&secp_ctx,
			);
			assert!(!network_graph.pending_checks.too_many_checks_pending());
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err();
		}
		assert!(network_graph.pending_checks.too_many_checks_pending());
		assert_eq!(pending_lookup_count(&network_graph), PendingChecks::MAX_PENDING_LOOKUPS + 1);
		assert_eq!(pending_message_count(&network_graph), PendingChecks::MAX_PENDING_LOOKUPS + 1);

		// Once the futures complete the "too many checks" flag should reset.
		for future in futures {
			future.resolve(Err(UtxoLookupError::UnknownTx));
		}
		assert!(notifier.notify_pending());
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(!network_graph.pending_checks.too_many_checks_pending());
		assert_eq!(pending_lookup_count(&network_graph), 0);
		assert_eq!(pending_message_count(&network_graph), 0);
	}

	#[test]
	fn test_checks_backpressure_same_scid() {
		// Distinct announcements for a single SCID share one lookup but are each queued, so they
		// must count towards backpressure.
		let secp_ctx = Secp256k1::new();
		let (chain_source, network_graph) = get_network();

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
		for i in 0..=PendingChecks::MAX_PENDING_MESSAGES {
			let node_1_privkey = &SecretKey::from_slice(&[100 + i as u8; 32]).unwrap();
			let announcement =
				get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
			assert_eq!(
				network_graph
					.update_channel_from_announcement(&announcement, &Some(&chain_source))
					.unwrap_err()
					.err,
				"Channel being checked async"
			);
		}
		assert_eq!(chain_source.get_utxo_call_count.load(Ordering::Relaxed), 1);
		assert_eq!(pending_lookup_count(&network_graph), 1);
		assert!(network_graph.pending_checks.too_many_checks_pending());

		future.resolve(Err(UtxoLookupError::UnknownTx));
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(!network_graph.pending_checks.too_many_checks_pending());
		assert_eq!(pending_lookup_count(&network_graph), 0);
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().nodes.is_empty());
	}

	#[test]
	fn test_checks_backpressure_updates() {
		// channel_updates queued behind a pending lookup count towards backpressure.
		let (valid_announcement, chain_source, network_graph, ..) = get_test_objects();

		let notifier = Arc::new(Notifier::new());
		let future = UtxoFuture::new(Arc::clone(&notifier));
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
		network_graph
			.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
			.unwrap_err();

		let secp_ctx = Secp256k1::new();
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		for i in 0..PendingChecks::MAX_PENDING_MESSAGES {
			assert!(!network_graph.pending_checks.too_many_checks_pending());
			let update = get_signed_channel_update(
				|msg| {
					msg.channel_flags = 0;
					msg.timestamp += i as u32;
				},
				node_1_privkey,
				&secp_ctx,
			);
			network_graph.update_channel(&update).unwrap_err();
		}
		assert!(network_graph.pending_checks.too_many_checks_pending());

		future.resolve(Err(UtxoLookupError::UnknownTx));
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(!network_graph.pending_checks.too_many_checks_pending());
		assert_eq!(pending_message_count(&network_graph), 0);
	}

	#[test]
	fn test_checks_backpressure_drop() {
		// Test that too_many_checks_pending returns true when there are many checks pending, and
		// returns false if we drop some of the futures without completion.
		let secp_ctx = Secp256k1::new();
		let (chain_source, network_graph) = get_network();

		let notifier = Arc::new(Notifier::new());
		let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
		let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

		let mut futures = Vec::new();
		for i in 0..=PendingChecks::MAX_PENDING_LOOKUPS {
			let future = UtxoFuture::new(Arc::clone(&notifier));
			*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());
			futures.push(future);
			let valid_announcement = get_signed_channel_announcement(
				|msg| msg.short_channel_id += i as u64,
				node_1_privkey,
				node_2_privkey,
				&secp_ctx,
			);
			assert!(!network_graph.pending_checks.too_many_checks_pending());
			network_graph
				.update_channel_from_announcement(&valid_announcement, &Some(&chain_source))
				.unwrap_err();
		}
		assert!(network_graph.pending_checks.too_many_checks_pending());

		// Once the futures are drop'd the "too many checks" flag should not yet reset to false.
		*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Err(UtxoLookupError::UnknownTx));
		drop(futures);
		assert!(network_graph.pending_checks.too_many_checks_pending());

		// .. but it should once we called check_resolved_futures clearing the pending lookups.
		network_graph.pending_checks.check_resolved_futures(&network_graph);
		assert!(!network_graph.pending_checks.too_many_checks_pending());
		assert_eq!(pending_lookup_count(&network_graph), 0);
		assert_eq!(pending_message_count(&network_graph), 0);
		assert!(network_graph.pending_checks.internal.lock().unwrap().channels.is_empty());
	}
}
