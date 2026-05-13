// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Test that monitor update failures don't get our channel state out of sync.
//! One of the biggest concern with the monitor update failure handling code is that messages
//! resent after monitor updating is restored are delivered out-of-order, resulting in
//! commitment_signed messages having "invalid signatures".
//! To test this we stand up a network of three nodes and read bytes from the fuzz input to denote
//! actions such as sending payments, handling events, or changing monitor update return values on
//! a per-node basis. This should allow it to find any cases where the ordering of actions results
//! in us getting out of sync with ourselves, and, assuming at least one of our recieve- or
//! send-side handling is correct, other peers. We consider it a failure if any action results in a
//! channel being force-closed.

use bitcoin::amount::Amount;
use bitcoin::constants::genesis_block;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::transaction::Version;
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::FeeRate;

use bitcoin::block::Header;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash as TraitImport;
use bitcoin::WPubkeyHash;

use lightning::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode};
use lightning::blinded_path::payment::{BlindedPaymentPath, ReceiveTlvs};
use lightning::chain;
use lightning::chain::chaininterface::{
	BroadcasterInterface, ConfirmationTarget, FeeEstimator, TransactionType,
};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::{
	chainmonitor, channelmonitor, BlockLocator, ChannelMonitorUpdateStatus, Confirm, Watch,
};
use lightning::events;
use lightning::ln::channel::{
	FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS,
};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{
	ChainParameters, ChannelManager, ChannelManagerReadArgs, PaymentId, RecentPaymentDetails,
	TrustedChannelFeatures,
};
use lightning::ln::functional_test_utils::*;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::msgs::{
	self, BaseMessageHandler, ChannelMessageHandler, CommitmentUpdate, Init, MessageSendEvent,
	UpdateAddHTLC,
};
use lightning::ln::outbound_payment::RecipientOnionFields;
use lightning::ln::script::ShutdownScript;
use lightning::ln::types::ChannelId;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath};
use lightning::routing::router::{
	InFlightHtlcs, Path, PaymentParameters, Route, RouteHop, RouteParameters, Router,
};
use lightning::sign::{
	EntropySource, InMemorySigner, NodeSigner, PeerStorageKey, ReceiveAuthKey, Recipient,
	SignerProvider,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::util::config::UserConfig;
use lightning::util::errors::APIError;
use lightning::util::hash_tables::*;
use lightning::util::logger::Logger;
use lightning::util::native_async::{MaybeSend, MaybeSync};
use lightning::util::ser::{LengthReadable, ReadableArgs, Writeable, Writer};
use lightning::util::test_channel_signer::{EnforcementState, SignerOp, TestChannelSigner};
use lightning::util::test_utils::TestWalletSource;
use lightning::util::wallet_utils::{WalletSourceSync, WalletSync};

use lightning_invoice::RawBolt11Invoice;

use crate::utils::test_logger::{self, Output};

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, Message, PublicKey, Scalar, Secp256k1, SecretKey};

use lightning::util::dyn_signer::DynSigner;

use std::cell::RefCell;
use std::cmp;
use std::collections::HashSet;
use std::mem;
use std::sync::atomic;
use std::sync::{Arc, Mutex};

const MAX_FEE: u32 = 10_000;
struct FuzzEstimator {
	ret_val: atomic::AtomicU32,
}

impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, conf_target: ConfirmationTarget) -> u32 {
		// We force-close channels if our counterparty sends us a feerate which is a small multiple
		// of our HighPriority fee estimate or smaller than our Background fee estimate. Thus, we
		// always return a HighPriority feerate here which is >= the maximum Normal feerate and a
		// Background feerate which is <= the minimum Normal feerate.
		match conf_target {
			ConfirmationTarget::MaximumFeeEstimate | ConfirmationTarget::UrgentOnChainSweep => {
				MAX_FEE
			},
			ConfirmationTarget::ChannelCloseMinimum
			| ConfirmationTarget::AnchorChannelFee
			| ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
			| ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee
			| ConfirmationTarget::OutputSpendingFee => 253,
			ConfirmationTarget::NonAnchorChannelFee => {
				cmp::min(self.ret_val.load(atomic::Ordering::Acquire), MAX_FEE)
			},
		}
	}
}

impl FuzzEstimator {
	fn feerate_sat_per_kw(&self) -> FeeRate {
		let feerate = self.ret_val.load(atomic::Ordering::Acquire);
		FeeRate::from_sat_per_kwu(feerate as u64)
	}
}

struct FuzzRouter {}

impl Router for FuzzRouter {
	fn find_route(
		&self, _payer: &PublicKey, _params: &RouteParameters,
		_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		unreachable!()
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs, _amount_msats: Option<u64>,
		_secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		unreachable!()
	}
}

impl MessageRouter for FuzzRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, _destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		unreachable!()
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_context: MessageContext, _peers: Vec<MessageForwardNode>, _secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		unreachable!()
	}
}

pub struct TestBroadcaster {
	txn_broadcasted: RefCell<Vec<Transaction>>,
}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transactions(&self, txs: &[(&Transaction, TransactionType)]) {
		for (tx, _broadcast_type) in txs {
			self.txn_broadcasted.borrow_mut().push((*tx).clone());
		}
	}
}

struct ChainState {
	blocks: Vec<(Header, Vec<Transaction>)>,
	confirmed_txids: HashSet<Txid>,
	/// Unconfirmed transactions (e.g., splice txs). Conflicting RBF candidates may coexist;
	/// `confirm_pending_txs` determines which one confirms.
	pending_txs: Vec<(Txid, Transaction)>,
}

impl ChainState {
	fn new() -> Self {
		let genesis_hash = genesis_block(Network::Bitcoin).block_hash();
		let genesis_header = create_dummy_header(genesis_hash, 42);
		Self {
			blocks: vec![(genesis_header, Vec::new())],
			confirmed_txids: HashSet::new(),
			pending_txs: Vec::new(),
		}
	}

	fn tip_height(&self) -> u32 {
		(self.blocks.len() - 1) as u32
	}

	fn is_outpoint_spent(&self, outpoint: &bitcoin::OutPoint) -> bool {
		self.blocks.iter().any(|(_, txs)| {
			txs.iter().any(|tx| tx.input.iter().any(|input| input.previous_output == *outpoint))
		})
	}

	fn confirm_tx(&mut self, tx: Transaction) -> bool {
		let txid = tx.compute_txid();
		if self.confirmed_txids.contains(&txid) {
			return false;
		}
		if tx.input.iter().any(|input| self.is_outpoint_spent(&input.previous_output)) {
			return false;
		}
		self.confirmed_txids.insert(txid);

		let prev_hash = self.blocks.last().unwrap().0.block_hash();
		let header = create_dummy_header(prev_hash, 42);
		self.blocks.push((header, vec![tx]));

		for _ in 0..5 {
			let prev_hash = self.blocks.last().unwrap().0.block_hash();
			let header = create_dummy_header(prev_hash, 42);
			self.blocks.push((header, Vec::new()));
		}
		true
	}

	/// Add a transaction to the pending pool (mempool). Multiple conflicting transactions (RBF
	/// candidates) may coexist; `confirm_pending_txs` selects which one to confirm.
	fn add_pending_tx(&mut self, tx: Transaction) {
		self.pending_txs.push((tx.compute_txid(), tx));
	}

	/// Confirm pending transactions in a single block, selecting deterministically among
	/// conflicting RBF candidates. Sorting by txid ensures the winner is determined by fuzz input
	/// content. Transactions that double-spend an already-confirmed outpoint are skipped.
	fn confirm_pending_txs(&mut self) {
		let mut txs = std::mem::take(&mut self.pending_txs);
		txs.sort_by_key(|(txid, _)| *txid);

		let mut confirmed = Vec::new();
		let mut spent_outpoints = Vec::new();
		for (txid, tx) in txs {
			if self.confirmed_txids.contains(&txid) {
				continue;
			}
			if tx.input.iter().any(|input| {
				self.is_outpoint_spent(&input.previous_output)
					|| spent_outpoints.contains(&input.previous_output)
			}) {
				continue;
			}
			self.confirmed_txids.insert(txid);
			for input in &tx.input {
				spent_outpoints.push(input.previous_output);
			}
			confirmed.push(tx);
		}

		if confirmed.is_empty() {
			return;
		}

		let prev_hash = self.blocks.last().unwrap().0.block_hash();
		let header = create_dummy_header(prev_hash, 42);
		self.blocks.push((header, confirmed));

		for _ in 0..5 {
			let prev_hash = self.blocks.last().unwrap().0.block_hash();
			let header = create_dummy_header(prev_hash, 42);
			self.blocks.push((header, Vec::new()));
		}
	}

	fn block_at(&self, height: u32) -> &(Header, Vec<Transaction>) {
		&self.blocks[height as usize]
	}
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::lightning::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

fn serialize_monitor(monitor: &ChannelMonitor<TestChannelSigner>) -> Vec<u8> {
	let mut ser = VecWriter(Vec::new());
	monitor.write(&mut ser).unwrap();
	ser.0
}

/// LDK requires the `ChannelMonitor` loaded on startup to be at least as current as the
/// `ChannelManager` state, except for monitor updates that `ChannelManager` still records as
/// in-flight and can replay. This harness tracks the monitor blobs that remain valid restart
/// candidates under that rule.
///
/// Separately, we track every `InProgress` persistence operation that still needs a
/// `channel_monitor_updated` call. A newer persisted monitor can make an older monitor invalid for
/// restart while the older update still needs to be completed to unblock the live `ChainMonitor`.
///
/// Off-chain monitor updates that are still "being persisted" are stored in `ChannelManager` and
/// will be replayed on startup. Full-monitor snapshots from chain sync or archive paths that return
/// `InProgress` are only restart candidates; losing one on restart does not require a
/// `channel_monitor_updated` callback.
struct LatestMonitorState {
	/// The latest monitor id which we told LDK we've persisted.
	///
	/// Note that earlier updates may still need a `channel_monitor_updated` callback via
	/// [`Self::pending_monitor_completions`].
	persisted_monitor_id: u64,
	/// The latest serialized `ChannelMonitor` that we told LDK we persisted.
	persisted_monitor: Vec<u8>,
	/// An ordered list of (monitor id, serialized `ChannelMonitor`)s which remain safe to use as
	/// stale monitors on reload.
	pending_monitors: Vec<(u64, Vec<u8>)>,
	/// An ordered list of (monitor id, serialized `ChannelMonitor`)s which still need a
	/// `channel_monitor_updated` callback.
	pending_monitor_completions: Vec<(u64, Vec<u8>)>,
}
impl LatestMonitorState {
	fn insert_pending_entry(
		pending: &mut Vec<(u64, Vec<u8>)>, monitor_id: u64, serialized_monitor: Vec<u8>,
	) {
		// Monitor update ids must arrive in order. Assert at insertion time so duplicates or
		// out-of-order updates fail close to the write that caused them instead of being sorted
		// into place.
		assert!(
			pending.last().map_or(true, |(last_id, _)| *last_id < monitor_id),
			"pending monitor updates should arrive in order"
		);
		pending.push((monitor_id, serialized_monitor));
	}

	fn insert_pending_monitor_candidate(&mut self, monitor_id: u64, serialized_monitor: Vec<u8>) {
		// Full-monitor persists from chain sync or archive paths use the monitor's current
		// latest_update_id rather than a fresh ChannelMonitorUpdate id. Keep duplicate ids so
		// reload can choose between multiple same-id full snapshots that were in flight together.
		if let Some((last_id, _)) = self.pending_monitors.last() {
			assert!(*last_id <= monitor_id, "pending monitor updates should arrive in order");
		}
		self.pending_monitors.push((monitor_id, serialized_monitor));
	}

	fn mark_persisted(&mut self, monitor_id: u64, serialized_monitor: Vec<u8>) {
		// Once a monitor is durable, use it as the restart baseline and stop tracking candidates
		// at or behind that update id. Completion obligations are tracked separately and are
		// deliberately not pruned here.
		self.pending_monitors.retain(|(id, _)| *id > monitor_id);
		if monitor_id >= self.persisted_monitor_id {
			self.persisted_monitor_id = monitor_id;
			self.persisted_monitor = serialized_monitor;
		}
	}

	fn insert_pending(
		&mut self, monitor_id: u64, serialized_monitor: Vec<u8>, needs_completion: bool,
	) {
		if needs_completion {
			// persist_new_channel and update_persisted_channel(Some(_)) require a later
			// channel_monitor_updated callback if persistence returns InProgress.
			Self::insert_pending_entry(
				&mut self.pending_monitors,
				monitor_id,
				serialized_monitor.clone(),
			);
			Self::insert_pending_entry(
				&mut self.pending_monitor_completions,
				monitor_id,
				serialized_monitor,
			);
		} else {
			// This harness treats update_persisted_channel(None, ...) as the chain-sync/archive
			// case: the full monitor may be used on restart, but ChainMonitor does not wait for a
			// channel_monitor_updated callback.
			self.insert_pending_monitor_candidate(monitor_id, serialized_monitor);
		}
	}

	fn mark_completed_update_persisted(&mut self, monitor_id: u64, serialized_monitor: Vec<u8>) {
		// The selector/drain path should already have removed this entry before
		// finish_monitor_update calls channel_monitor_updated. This check catches accidental
		// double-completion or pruning of the wrong list.
		assert!(
			self.pending_monitor_completions.iter().all(|(id, _)| *id != monitor_id),
			"completed monitor update should already be removed from the completion queue"
		);
		self.mark_persisted(monitor_id, serialized_monitor);
	}

	fn drain_pending_completions(&mut self) -> Vec<(u64, Vec<u8>)> {
		std::mem::take(&mut self.pending_monitor_completions)
	}

	fn take_pending_completion(
		&mut self, selector: MonitorUpdateSelector,
	) -> Option<(u64, Vec<u8>)> {
		// The fuzzer chooses which outstanding callback to deliver. These choices apply to
		// completion obligations, not to the set of monitors that may be used on restart.
		match selector {
			MonitorUpdateSelector::First => {
				if self.pending_monitor_completions.is_empty() {
					None
				} else {
					Some(self.pending_monitor_completions.remove(0))
				}
			},
			MonitorUpdateSelector::Second => {
				if self.pending_monitor_completions.len() > 1 {
					Some(self.pending_monitor_completions.remove(1))
				} else {
					None
				}
			},
			MonitorUpdateSelector::Last => self.pending_monitor_completions.pop(),
		}
	}

	fn select_monitor_for_reload(&mut self, selector: MonitorReloadSelector) {
		// A restart can load the last monitor we told LDK was persisted, or a monitor snapshot
		// whose write was started before the simulated crash.
		let old_mon = (self.persisted_monitor_id, std::mem::take(&mut self.persisted_monitor));
		let (monitor_id, serialized_monitor) = match selector {
			MonitorReloadSelector::Persisted => old_mon,
			MonitorReloadSelector::FirstPending => {
				if self.pending_monitors.is_empty() {
					old_mon
				} else {
					self.pending_monitors.remove(0)
				}
			},
			MonitorReloadSelector::LastPending => self.pending_monitors.pop().unwrap_or(old_mon),
		};
		self.persisted_monitor_id = monitor_id;
		self.persisted_monitor = serialized_monitor;
		// After restart, stop tracking pre-restart in-flight writes. ChannelManager will replay
		// off-chain monitor updates that still matter; full-monitor snapshots may simply be absent.
		self.pending_monitors.clear();
		self.pending_monitor_completions.clear();
	}
}

struct HarnessPersister {
	pub update_ret: Mutex<chain::ChannelMonitorUpdateStatus>,
	pub latest_monitors: Mutex<HashMap<ChannelId, LatestMonitorState>>,
}
impl HarnessPersister {
	fn track_monitor_update(
		&self, channel_id: ChannelId, monitor_id: u64, serialized_monitor: Vec<u8>,
		status: chain::ChannelMonitorUpdateStatus, needs_completion: bool,
	) {
		let mut latest_monitors = self.latest_monitors.lock().unwrap();
		if let Some(state) = latest_monitors.get_mut(&channel_id) {
			match status {
				chain::ChannelMonitorUpdateStatus::Completed => {
					// A completed write advances the restart baseline. Once LDK can rely on that
					// monitor state being durable, the harness stops offering candidates at or
					// behind that update id.
					state.mark_persisted(monitor_id, serialized_monitor);
				},
				chain::ChannelMonitorUpdateStatus::InProgress => {
					// InProgress always creates a restart candidate, but only some calls also need
					// an explicit channel_monitor_updated completion.
					state.insert_pending(monitor_id, serialized_monitor, needs_completion);
				},
				chain::ChannelMonitorUpdateStatus::UnrecoverableError => {},
			}
		} else {
			let state = match status {
				chain::ChannelMonitorUpdateStatus::Completed => LatestMonitorState {
					persisted_monitor_id: monitor_id,
					persisted_monitor: serialized_monitor,
					pending_monitors: Vec::new(),
					pending_monitor_completions: Vec::new(),
				},
				chain::ChannelMonitorUpdateStatus::InProgress => {
					// The first persist for a channel is persist_new_channel, which always needs a
					// completion callback when it returns InProgress. A full-monitor update without
					// existing state would mean the harness missed the channel's initial monitor.
					assert!(needs_completion, "missing monitor state for full monitor update");
					LatestMonitorState {
						persisted_monitor_id: monitor_id,
						persisted_monitor: Vec::new(),
						pending_monitors: vec![(monitor_id, serialized_monitor.clone())],
						pending_monitor_completions: vec![(monitor_id, serialized_monitor)],
					}
				},
				chain::ChannelMonitorUpdateStatus::UnrecoverableError => return,
			};
			assert!(
				latest_monitors.insert(channel_id, state).is_none(),
				"Already had monitor state pre-persist"
			);
		}
	}

	fn mark_update_completed(
		&self, channel_id: ChannelId, monitor_id: u64, serialized_monitor: Vec<u8>,
	) {
		let mut latest_monitors = self.latest_monitors.lock().unwrap();
		let state = latest_monitors
			.get_mut(&channel_id)
			.expect("missing monitor state for completed update");
		// Once we tell LDK update N is completed, use the completed monitor as the restart
		// baseline and drop restart candidates at or behind N.
		state.mark_completed_update_persisted(monitor_id, serialized_monitor);
	}

	fn drain_pending_updates(&self, channel_id: &ChannelId) -> Vec<(u64, Vec<u8>)> {
		self.latest_monitors
			.lock()
			.unwrap()
			.get_mut(channel_id)
			.map_or_else(Vec::new, |state| state.drain_pending_completions())
	}

	fn drain_all_pending_updates(&self) -> Vec<(ChannelId, u64, Vec<u8>)> {
		let mut completed_updates = Vec::new();
		for (channel_id, state) in self.latest_monitors.lock().unwrap().iter_mut() {
			for (monitor_id, data) in state.drain_pending_completions() {
				completed_updates.push((*channel_id, monitor_id, data));
			}
		}
		completed_updates
	}

	fn take_pending_update(
		&self, channel_id: &ChannelId, selector: MonitorUpdateSelector,
	) -> Option<(u64, Vec<u8>)> {
		self.latest_monitors
			.lock()
			.unwrap()
			.get_mut(channel_id)
			.and_then(|state| state.take_pending_completion(selector))
	}
}
impl chainmonitor::Persist<TestChannelSigner> for HarnessPersister {
	fn persist_new_channel(
		&self, _monitor_name: lightning::util::persist::MonitorName,
		data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		let status = self.update_ret.lock().unwrap().clone();
		let monitor_id = data.get_latest_update_id();
		let serialized_monitor = serialize_monitor(data);
		self.track_monitor_update(data.channel_id(), monitor_id, serialized_monitor, status, true);
		status
	}

	fn update_persisted_channel(
		&self, _monitor_name: lightning::util::persist::MonitorName,
		update: Option<&channelmonitor::ChannelMonitorUpdate>,
		data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		let status = self.update_ret.lock().unwrap().clone();
		let monitor_id = update.map_or_else(|| data.get_latest_update_id(), |upd| upd.update_id);
		let serialized_monitor = serialize_monitor(data);
		self.track_monitor_update(
			data.channel_id(),
			monitor_id,
			serialized_monitor,
			status,
			// `None` normally comes from chain-sync or archive writes, which need no completion
			// callback. `update_channel_internal` can also use `None` after `update_monitor`
			// fails, but this harness does not model that error-recovery path.
			update.is_some(),
		);
		status
	}

	fn archive_persisted_channel(&self, _monitor_name: lightning::util::persist::MonitorName) {}
}

type TestChainMonitor = chainmonitor::ChainMonitor<
	TestChannelSigner,
	Arc<dyn chain::Filter>,
	Arc<TestBroadcaster>,
	Arc<FuzzEstimator>,
	Arc<dyn Logger + MaybeSend + MaybeSync>,
	Arc<HarnessPersister>,
	Arc<KeyProvider>,
>;

struct KeyProvider {
	node_secret: SecretKey,
	rand_bytes_id: atomic::AtomicU32,
	enforcement_states: Mutex<HashMap<[u8; 32], Arc<Mutex<EnforcementState>>>>,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		#[rustfmt::skip]
		let mut res = [self.node_secret[31], 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, self.node_secret[31]];
		res[2..6].copy_from_slice(&id.to_le_bytes());
		res[30 - 4..30].copy_from_slice(&id.to_le_bytes());
		res
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_expanded_key(&self) -> ExpandedKey {
		#[rustfmt::skip]
		let random_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, self.node_secret[31]];
		ExpandedKey::new(random_bytes)
	}

	fn sign_invoice(
		&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		PeerStorageKey { inner: [42; 32] }
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		ReceiveAuthKey([41; 32])
	}

	fn sign_bolt12_invoice(
		&self, _invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(
		&self, msg: lightning::ln::msgs::UnsignedGossipMessage,
	) -> Result<Signature, ()> {
		let msg_hash = Message::from_digest(Sha256dHash::hash(&msg.encode()[..]).to_byte_array());
		let secp_ctx = Secp256k1::signing_only();
		Ok(secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		Ok(lightning::util::message_signing::sign(msg, &self.node_secret))
	}
}

impl SignerProvider for KeyProvider {
	type EcdsaSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _user_channel_id: u128) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed) as u8;
		[id; 32]
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		let id = channel_keys_id[0];
		#[rustfmt::skip]
		let keys = InMemorySigner::new(
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_secret[31]]).unwrap(),
			// We leave both the v1 and v2 derivation to_remote keys the same as there's not any
			// real reason to fuzz differences here.
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_secret[31]]).unwrap(),
			true,
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_secret[31]]).unwrap(),
			[id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_secret[31]],
			channel_keys_id,
			channel_keys_id,
		);
		let revoked_commitment = self.make_enforcement_state_cell(keys.commitment_seed);
		let keys = DynSigner::new(keys);
		TestChannelSigner::new_with_revoked(keys, revoked_commitment, false, false)
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		let secp_ctx = Secp256k1::signing_only();
		#[rustfmt::skip]
		let channel_monitor_claim_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, self.node_secret[31]]).unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(
			&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize(),
		);
		Ok(Builder::new()
			.push_opcode(opcodes::all::OP_PUSHBYTES_0)
			.push_slice(our_channel_monitor_claim_key_hash)
			.into_script())
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		let secp_ctx = Secp256k1::signing_only();
		#[rustfmt::skip]
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, self.node_secret[31]]).unwrap();
		let pubkey_hash =
			WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &secret_key).serialize());
		Ok(ShutdownScript::new_p2wpkh(&pubkey_hash))
	}
}

// Since this fuzzer is only concerned with live-channel operations, we don't need to worry about
// any signer operations that come after a force close.
const SUPPORTED_SIGNER_OPS: [SignerOp; 3] = [
	SignerOp::SignCounterpartyCommitment,
	SignerOp::GetPerCommitmentPoint,
	SignerOp::ReleaseCommitmentSecret,
];

impl KeyProvider {
	fn make_enforcement_state_cell(
		&self, commitment_seed: [u8; 32],
	) -> Arc<Mutex<EnforcementState>> {
		let mut revoked_commitments = self.enforcement_states.lock().unwrap();
		if !revoked_commitments.contains_key(&commitment_seed) {
			revoked_commitments
				.insert(commitment_seed, Arc::new(Mutex::new(EnforcementState::new())));
		}
		let cell = revoked_commitments.get(&commitment_seed).unwrap();
		Arc::clone(cell)
	}

	fn disable_supported_ops_for_all_signers(&self) {
		let enforcement_states = self.enforcement_states.lock().unwrap();
		for (_, state) in enforcement_states.iter() {
			for signer_op in SUPPORTED_SIGNER_OPS {
				state.lock().unwrap().disabled_signer_ops.insert(signer_op);
			}
		}
	}

	fn enable_op_for_all_signers(&self, signer_op: SignerOp) {
		let enforcement_states = self.enforcement_states.lock().unwrap();
		for (_, state) in enforcement_states.iter() {
			state.lock().unwrap().disabled_signer_ops.remove(&signer_op);
		}
	}
}

type ChanMan<'a> = ChannelManager<
	Arc<TestChainMonitor>,
	Arc<TestBroadcaster>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<FuzzEstimator>,
	&'a FuzzRouter,
	&'a FuzzRouter,
	Arc<dyn Logger + MaybeSend + MaybeSync>,
>;

#[inline]
fn assert_action_timeout_awaiting_response(action: &msgs::ErrorAction) {
	// Since sending/receiving messages may be delayed, `timer_tick_occurred` may cause a node to
	// disconnect their counterparty if they're expecting a timely response.
	assert!(
		matches!(
			action,
			msgs::ErrorAction::DisconnectPeerWithWarning { msg }
			if msg.data.contains("Disconnecting due to timeout awaiting response")
				|| msg.data.contains("already sent splice_locked, cannot RBF")
		),
		"Expected timeout disconnect, got: {:?}",
		action,
	);
}

#[derive(Clone, Copy, PartialEq)]
enum ChanType {
	Legacy,
	KeyedAnchors,
	ZeroFeeCommitments,
}

// While delivering messages, select across three possible message selection
// processes to maximize coverage. See the individual enum variants for details.
#[derive(Copy, Clone, PartialEq, Eq)]
enum ProcessMessages {
	/// Deliver all available messages, including fetching any new messages from
	/// `get_and_clear_pending_msg_events()` which may have side effects.
	AllMessages,
	/// Call `get_and_clear_pending_msg_events()` first, then deliver up to one
	/// message, which may already be queued.
	OneMessage,
	/// Deliver up to one already-queued message. This avoids the side effects of
	/// `get_and_clear_pending_msg_events()`, such as freeing the HTLC holding cell.
	OnePendingMessage,
}

struct HarnessNode<'a> {
	node_id: u8,
	node: ChanMan<'a>,
	monitor: Arc<TestChainMonitor>,
	persister: Arc<HarnessPersister>,
	keys_manager: Arc<KeyProvider>,
	logger: Arc<dyn Logger + MaybeSend + MaybeSync>,
	broadcaster: Arc<TestBroadcaster>,
	fee_estimator: Arc<FuzzEstimator>,
	wallet: TestWalletSource,
	persistence_style: ChannelMonitorUpdateStatus,
	serialized_manager: Vec<u8>,
	height: u32,
	last_htlc_clear_fee: u32,
}

impl<'a> std::ops::Deref for HarnessNode<'a> {
	type Target = ChanMan<'a>;

	fn deref(&self) -> &Self::Target {
		&self.node
	}
}

impl<'a> HarnessNode<'a> {
	fn build_logger<Out: Output + MaybeSend + MaybeSync>(
		node_id: u8, out: &Out,
	) -> Arc<dyn Logger + MaybeSend + MaybeSync> {
		Arc::new(test_logger::TestLogger::new(node_id.to_string(), out.clone()))
	}

	fn build_persister(persistence_style: ChannelMonitorUpdateStatus) -> Arc<HarnessPersister> {
		Arc::new(HarnessPersister {
			update_ret: Mutex::new(persistence_style),
			latest_monitors: Mutex::new(new_hash_map()),
		})
	}

	fn build_chain_monitor(
		broadcaster: &Arc<TestBroadcaster>, fee_estimator: &Arc<FuzzEstimator>,
		keys_manager: &Arc<KeyProvider>, logger: Arc<dyn Logger + MaybeSend + MaybeSync>,
		persister: &Arc<HarnessPersister>,
	) -> Arc<TestChainMonitor> {
		Arc::new(chainmonitor::ChainMonitor::new(
			None,
			Arc::clone(broadcaster),
			logger,
			Arc::clone(fee_estimator),
			Arc::clone(persister),
			Arc::clone(keys_manager),
			keys_manager.get_peer_storage_key(),
			false,
		))
	}

	fn new<Out: Output + MaybeSend + MaybeSync>(
		node_id: u8, wallet: TestWalletSource, fee_estimator: Arc<FuzzEstimator>,
		broadcaster: Arc<TestBroadcaster>, persistence_style: ChannelMonitorUpdateStatus,
		out: &Out, router: &'a FuzzRouter, chan_type: ChanType,
	) -> Self {
		let logger = Self::build_logger(node_id, out);
		let node_secret = SecretKey::from_slice(&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 1, node_id,
		])
		.unwrap();
		let keys_manager = Arc::new(KeyProvider {
			node_secret,
			rand_bytes_id: atomic::AtomicU32::new(0),
			enforcement_states: Mutex::new(new_hash_map()),
		});
		let persister = Self::build_persister(persistence_style);
		let monitor = Self::build_chain_monitor(
			&broadcaster,
			&fee_estimator,
			&keys_manager,
			Arc::clone(&logger),
			&persister,
		);
		let network = Network::Bitcoin;
		let best_block_timestamp = genesis_block(network).header.time;
		let params = ChainParameters { network, best_block: BlockLocator::from_network(network) };
		let node = ChannelManager::new(
			Arc::clone(&fee_estimator),
			Arc::clone(&monitor),
			Arc::clone(&broadcaster),
			router,
			router,
			Arc::clone(&logger),
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			build_node_config(chan_type),
			params,
			best_block_timestamp,
		);
		Self {
			node_id,
			node,
			monitor,
			persister,
			keys_manager,
			logger,
			broadcaster,
			fee_estimator,
			wallet,
			persistence_style,
			serialized_manager: Vec::new(),
			height: 0,
			last_htlc_clear_fee: 253,
		}
	}

	fn set_persistence_style(&mut self, style: ChannelMonitorUpdateStatus) {
		// Store the style for the next reload. The active persister is intentionally not changed
		// in place.
		self.persistence_style = style;
	}

	fn finish_monitor_update(&self, chan_id: ChannelId, monitor_id: u64, data: Vec<u8>) {
		self.monitor.channel_monitor_updated(chan_id, monitor_id).unwrap();
		self.persister.mark_update_completed(chan_id, monitor_id, data);
	}

	fn complete_all_monitor_updates(&self, chan_id: &ChannelId) -> bool {
		let completed_updates = self.persister.drain_pending_updates(chan_id);
		let completed_any = !completed_updates.is_empty();
		for (monitor_id, data) in completed_updates {
			self.finish_monitor_update(*chan_id, monitor_id, data);
		}
		completed_any
	}

	fn complete_all_pending_monitor_updates(&self) {
		for (channel_id, monitor_id, data) in self.persister.drain_all_pending_updates() {
			self.finish_monitor_update(channel_id, monitor_id, data);
		}
	}

	fn complete_monitor_update(&self, chan_id: &ChannelId, selector: MonitorUpdateSelector) {
		if let Some((monitor_id, data)) = self.persister.take_pending_update(chan_id, selector) {
			self.finish_monitor_update(*chan_id, monitor_id, data);
		}
	}

	fn sync_with_chain_state(&mut self, chain_state: &ChainState, num_blocks: Option<u32>) {
		let target_height = if let Some(num_blocks) = num_blocks {
			std::cmp::min(self.height + num_blocks, chain_state.tip_height())
		} else {
			chain_state.tip_height()
		};

		while self.height < target_height {
			self.height += 1;
			let (header, txn) = chain_state.block_at(self.height);
			let txdata: Vec<_> = txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			if !txdata.is_empty() {
				self.node.transactions_confirmed(header, &txdata, self.height);
			}
			self.node.best_block_updated(header, self.height);
		}
	}

	fn refresh_serialized_manager(&mut self) -> bool {
		if self.node.get_and_clear_needs_persistence() {
			self.serialized_manager = self.node.encode();
			true
		} else {
			false
		}
	}

	fn bump_fee_estimate(&mut self, chan_type: ChanType) {
		let mut max_feerate = self.last_htlc_clear_fee;
		if matches!(chan_type, ChanType::Legacy) {
			max_feerate *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
		}
		if self.fee_estimator.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
			self.fee_estimator.ret_val.store(max_feerate, atomic::Ordering::Release);
		}
		self.node.timer_tick_occurred();
	}

	fn reset_fee_estimate(&self) {
		self.fee_estimator.ret_val.store(253, atomic::Ordering::Release);
		self.node.timer_tick_occurred();
	}

	fn current_feerate_sat_per_kw(&self) -> FeeRate {
		self.fee_estimator.feerate_sat_per_kw()
	}

	fn record_last_htlc_clear_fee(&mut self) {
		self.last_htlc_clear_fee = self.fee_estimator.ret_val.load(atomic::Ordering::Acquire);
	}

	fn splice_in(&self, counterparty_node_id: &PublicKey, channel_id: &ChannelId) {
		let wallet = WalletSync::new(&self.wallet, Arc::clone(&self.logger));
		match self.node.splice_channel(channel_id, counterparty_node_id) {
			Ok(funding_template) => {
				let feerate =
					funding_template.min_rbf_feerate().unwrap_or(self.current_feerate_sat_per_kw());
				if let Ok(contribution) = funding_template.splice_in_sync(
					Amount::from_sat(10_000),
					feerate,
					FeeRate::MAX,
					&wallet,
				) {
					let _ = self.node.funding_contributed(
						channel_id,
						counterparty_node_id,
						contribution,
						None,
					);
				}
			},
			Err(e) => {
				assert!(
					matches!(e, APIError::APIMisuseError { ref err } if err.contains("splice")),
					"{:?}",
					e
				);
			},
		}
	}

	fn splice_out(&self, counterparty_node_id: &PublicKey, channel_id: &ChannelId) {
		// We conditionally splice out `MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS` only when the node
		// has double the balance required to send a payment upon a `0xff` byte. We do this to
		// ensure there's always liquidity available for a payment to succeed then.
		let outbound_capacity_msat = self
			.node
			.list_channels()
			.iter()
			.find(|chan| chan.channel_id == *channel_id)
			.map(|chan| chan.outbound_capacity_msat)
			.unwrap();
		if outbound_capacity_msat < 20_000_000 {
			return;
		}
		match self.node.splice_channel(channel_id, counterparty_node_id) {
			Ok(funding_template) => {
				let feerate =
					funding_template.min_rbf_feerate().unwrap_or(self.current_feerate_sat_per_kw());
				let outputs = vec![TxOut {
					value: Amount::from_sat(MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS),
					script_pubkey: self.wallet.get_change_script().unwrap(),
				}];
				if let Ok(contribution) =
					funding_template.splice_out(outputs, feerate, FeeRate::MAX)
				{
					let _ = self.node.funding_contributed(
						channel_id,
						counterparty_node_id,
						contribution,
						None,
					);
				}
			},
			Err(e) => {
				assert!(
					matches!(e, APIError::APIMisuseError { ref err } if err.contains("splice")),
					"{:?}",
					e
				);
			},
		}
	}

	fn reload<Out: Output + MaybeSend + MaybeSync>(
		&mut self, use_old_mons: u8, out: &Out, router: &'a FuzzRouter, chan_type: ChanType,
	) {
		let logger = Self::build_logger(self.node_id, out);
		let persister = Self::build_persister(self.persistence_style);
		let chain_monitor = Self::build_chain_monitor(
			&self.broadcaster,
			&self.fee_estimator,
			&self.keys_manager,
			Arc::clone(&logger),
			&persister,
		);

		let mut monitors = new_hash_map();
		let mut use_old_mons = use_old_mons;
		{
			let mut old_monitors = self.persister.latest_monitors.lock().unwrap();
			for (channel_id, mut prev_state) in old_monitors.drain() {
				let selector = match use_old_mons % 3 {
					0 => MonitorReloadSelector::Persisted,
					1 => MonitorReloadSelector::FirstPending,
					_ => MonitorReloadSelector::LastPending,
				};
				prev_state.select_monitor_for_reload(selector);
				// Use a different trit for each monitor so one restart byte can vary the stale
				// monitor depth across multiple monitors for the node.
				use_old_mons /= 3;
				let mon = <(BlockLocator, ChannelMonitor<TestChannelSigner>)>::read(
					&mut &prev_state.persisted_monitor[..],
					(&*self.keys_manager, &*self.keys_manager),
				)
				.expect("Failed to read monitor");
				monitors.insert(channel_id, mon.1);
				persister.latest_monitors.lock().unwrap().insert(channel_id, prev_state);
			}
		}
		let mut monitor_refs = new_hash_map();
		for (channel_id, monitor) in monitors.iter() {
			monitor_refs.insert(*channel_id, monitor);
		}

		let read_args = ChannelManagerReadArgs {
			entropy_source: Arc::clone(&self.keys_manager),
			node_signer: Arc::clone(&self.keys_manager),
			signer_provider: Arc::clone(&self.keys_manager),
			fee_estimator: Arc::clone(&self.fee_estimator),
			chain_monitor: Arc::clone(&chain_monitor),
			tx_broadcaster: Arc::clone(&self.broadcaster),
			router,
			message_router: router,
			logger: Arc::clone(&logger),
			config: build_node_config(chan_type),
			channel_monitors: monitor_refs,
		};

		let manager = <(BlockLocator, ChanMan)>::read(&mut &self.serialized_manager[..], read_args)
			.expect("Failed to read manager");
		for (channel_id, mon) in monitors.drain() {
			assert_eq!(chain_monitor.watch_channel(channel_id, mon), Ok(self.persistence_style));
		}
		self.node = manager.1;
		self.monitor = chain_monitor;
		self.persister = persister;
		self.logger = logger;
	}
}

#[derive(Copy, Clone)]
enum MonitorReloadSelector {
	Persisted,
	FirstPending,
	LastPending,
}

#[derive(Copy, Clone)]
enum MonitorUpdateSelector {
	First,
	Second,
	Last,
}

#[derive(Copy, Clone)]
enum MppDirectChannels {
	All,
	RepeatedFirst,
}

#[derive(Copy, Clone)]
enum MppHopChannels {
	FirstHop,
	BothHops,
	SecondHop,
}

struct EventQueues {
	ab: Vec<MessageSendEvent>,
	ba: Vec<MessageSendEvent>,
	bc: Vec<MessageSendEvent>,
	cb: Vec<MessageSendEvent>,
}

impl EventQueues {
	fn new() -> Self {
		Self { ab: Vec::new(), ba: Vec::new(), bc: Vec::new(), cb: Vec::new() }
	}

	fn take_for_node(&mut self, node_idx: usize) -> Vec<MessageSendEvent> {
		match node_idx {
			0 => {
				let mut events = Vec::new();
				mem::swap(&mut events, &mut self.ab);
				events
			},
			1 => {
				let mut events = Vec::new();
				mem::swap(&mut events, &mut self.ba);
				events.extend_from_slice(&self.bc[..]);
				self.bc.clear();
				events
			},
			2 => {
				let mut events = Vec::new();
				mem::swap(&mut events, &mut self.cb);
				events
			},
			_ => panic!("invalid node index"),
		}
	}

	fn push_for_node(&mut self, node_idx: usize, event: MessageSendEvent) {
		match node_idx {
			0 => self.ab.push(event),
			2 => self.cb.push(event),
			_ => panic!("cannot directly queue messages for node {}", node_idx),
		}
	}

	fn extend_for_node<I: IntoIterator<Item = MessageSendEvent>>(
		&mut self, node_idx: usize, events: I,
	) {
		match node_idx {
			0 => self.ab.extend(events),
			2 => self.cb.extend(events),
			_ => panic!("cannot directly queue messages for node {}", node_idx),
		}
	}

	fn route_from_middle<'a, I: IntoIterator<Item = MessageSendEvent>>(
		&mut self, excess_events: I, expect_drop_node: Option<usize>, nodes: &[HarnessNode<'a>; 3],
	) {
		// Push any events from Node B onto queues.ba and queues.bc.
		let a_id = nodes[0].get_our_node_id();
		let expect_drop_id = expect_drop_node.map(|id| nodes[id].get_our_node_id());
		for event in excess_events {
			let push_a = match event {
				MessageSendEvent::UpdateHTLCs { ref node_id, .. }
				| MessageSendEvent::SendRevokeAndACK { ref node_id, .. }
				| MessageSendEvent::SendChannelReestablish { ref node_id, .. }
				| MessageSendEvent::SendStfu { ref node_id, .. }
				| MessageSendEvent::SendSpliceInit { ref node_id, .. }
				| MessageSendEvent::SendSpliceAck { ref node_id, .. }
				| MessageSendEvent::SendSpliceLocked { ref node_id, .. }
				| MessageSendEvent::SendTxAddInput { ref node_id, .. }
				| MessageSendEvent::SendTxAddOutput { ref node_id, .. }
				| MessageSendEvent::SendTxRemoveInput { ref node_id, .. }
				| MessageSendEvent::SendTxRemoveOutput { ref node_id, .. }
				| MessageSendEvent::SendTxComplete { ref node_id, .. }
				| MessageSendEvent::SendTxAbort { ref node_id, .. }
				| MessageSendEvent::SendTxInitRbf { ref node_id, .. }
				| MessageSendEvent::SendTxAckRbf { ref node_id, .. }
				| MessageSendEvent::SendTxSignatures { ref node_id, .. }
				| MessageSendEvent::SendChannelUpdate { ref node_id, .. } => {
					if Some(*node_id) == expect_drop_id {
						panic!(
							"peer_disconnected should drop msgs bound for the disconnected peer"
						);
					}
					*node_id == a_id
				},
				MessageSendEvent::HandleError { ref action, ref node_id } => {
					assert_action_timeout_awaiting_response(action);
					if Some(*node_id) == expect_drop_id {
						panic!(
							"peer_disconnected should drop msgs bound for the disconnected peer"
						);
					}
					*node_id == a_id
				},
				MessageSendEvent::SendChannelReady { .. }
				| MessageSendEvent::SendAnnouncementSignatures { .. }
				| MessageSendEvent::BroadcastChannelUpdate { .. } => continue,
				_ => panic!("Unhandled message event {:?}", event),
			};
			if push_a {
				self.ba.push(event);
			} else {
				self.bc.push(event);
			}
		}
	}

	fn clear_link(&mut self, link: &PeerLink) {
		match (link.node_a, link.node_b) {
			(0, 1) | (1, 0) => {
				self.ab.clear();
				self.ba.clear();
			},
			(1, 2) | (2, 1) => {
				self.bc.clear();
				self.cb.clear();
			},
			_ => panic!("unsupported link"),
		}
	}

	fn drain_on_disconnect(&mut self, edge_node: usize, nodes: &[HarnessNode<'_>; 3]) {
		match edge_node {
			0 => {
				for event in nodes[0].get_and_clear_pending_msg_events() {
					match event {
						MessageSendEvent::UpdateHTLCs { .. } => {},
						MessageSendEvent::SendRevokeAndACK { .. } => {},
						MessageSendEvent::SendChannelReestablish { .. } => {},
						MessageSendEvent::SendStfu { .. } => {},
						MessageSendEvent::SendChannelReady { .. } => {},
						MessageSendEvent::SendAnnouncementSignatures { .. } => {},
						MessageSendEvent::BroadcastChannelUpdate { .. } => {},
						MessageSendEvent::SendChannelUpdate { .. } => {},
						MessageSendEvent::HandleError { ref action, .. } => {
							assert_action_timeout_awaiting_response(action);
						},
						_ => panic!("Unhandled message event"),
					}
				}
				self.route_from_middle(nodes[1].get_and_clear_pending_msg_events(), Some(0), nodes);
			},
			2 => {
				for event in nodes[2].get_and_clear_pending_msg_events() {
					match event {
						MessageSendEvent::UpdateHTLCs { .. } => {},
						MessageSendEvent::SendRevokeAndACK { .. } => {},
						MessageSendEvent::SendChannelReestablish { .. } => {},
						MessageSendEvent::SendStfu { .. } => {},
						MessageSendEvent::SendChannelReady { .. } => {},
						MessageSendEvent::SendAnnouncementSignatures { .. } => {},
						MessageSendEvent::BroadcastChannelUpdate { .. } => {},
						MessageSendEvent::SendChannelUpdate { .. } => {},
						MessageSendEvent::HandleError { ref action, .. } => {
							assert_action_timeout_awaiting_response(action);
						},
						_ => panic!("Unhandled message event"),
					}
				}
				self.route_from_middle(nodes[1].get_and_clear_pending_msg_events(), Some(2), nodes);
			},
			_ => panic!("unsupported disconnected edge"),
		}
	}
}

struct PeerLink {
	node_a: usize,
	node_b: usize,
	channel_ids: [ChannelId; 3],
	disconnected: bool,
}

impl PeerLink {
	fn new(node_a: usize, node_b: usize, channel_ids: [ChannelId; 3]) -> Self {
		Self { node_a, node_b, channel_ids, disconnected: false }
	}

	fn first_channel_id(&self) -> ChannelId {
		self.channel_ids[0]
	}

	fn channel_ids(&self) -> &[ChannelId; 3] {
		&self.channel_ids
	}

	fn connects(&self, node_a: usize, node_b: usize) -> bool {
		(self.node_a == node_a && self.node_b == node_b)
			|| (self.node_a == node_b && self.node_b == node_a)
	}

	fn complete_all_monitor_updates(&self, nodes: &[HarnessNode<'_>; 3]) -> bool {
		let mut completed_updates = false;
		for id in &self.channel_ids {
			completed_updates |= nodes[self.node_a].complete_all_monitor_updates(id);
			completed_updates |= nodes[self.node_b].complete_all_monitor_updates(id);
		}
		completed_updates
	}

	fn complete_monitor_updates_for_node(
		&self, node_idx: usize, nodes: &[HarnessNode<'_>; 3], selector: MonitorUpdateSelector,
	) {
		assert!(node_idx == self.node_a || node_idx == self.node_b);
		for id in &self.channel_ids {
			nodes[node_idx].complete_monitor_update(id, selector);
		}
	}

	fn disconnect(&mut self, nodes: &[HarnessNode<'_>; 3], queues: &mut EventQueues) {
		if self.disconnected {
			return;
		}
		let node_a_id = nodes[self.node_a].get_our_node_id();
		let node_b_id = nodes[self.node_b].get_our_node_id();
		nodes[self.node_a].peer_disconnected(node_b_id);
		nodes[self.node_b].peer_disconnected(node_a_id);
		self.disconnected = true;
		let edge_node = if self.node_a == 1 {
			self.node_b
		} else if self.node_b == 1 {
			self.node_a
		} else {
			panic!("unsupported link topology")
		};
		queues.drain_on_disconnect(edge_node, nodes);
		queues.clear_link(self);
	}

	fn reconnect(&mut self, nodes: &[HarnessNode<'_>; 3]) {
		if !self.disconnected {
			return;
		}
		let node_a_id = nodes[self.node_a].get_our_node_id();
		let node_b_id = nodes[self.node_b].get_our_node_id();
		let init_b = Init {
			features: nodes[self.node_b].init_features(),
			networks: None,
			remote_network_address: None,
		};
		nodes[self.node_a].peer_connected(node_b_id, &init_b, true).unwrap();
		let init_a = Init {
			features: nodes[self.node_a].init_features(),
			networks: None,
			remote_network_address: None,
		};
		nodes[self.node_b].peer_connected(node_a_id, &init_a, false).unwrap();
		self.disconnected = false;
	}

	fn disconnect_for_reload(
		&mut self, restarted_node: usize, nodes: &[HarnessNode<'_>; 3], queues: &mut EventQueues,
	) {
		if self.disconnected {
			return;
		}
		assert!(restarted_node == self.node_a || restarted_node == self.node_b);

		let remaining_node = if restarted_node == self.node_a { self.node_b } else { self.node_a };
		let restarted_node_id = nodes[restarted_node].get_our_node_id();
		nodes[remaining_node].peer_disconnected(restarted_node_id);
		self.disconnected = true;

		if remaining_node == 1 {
			queues.route_from_middle(
				nodes[1].get_and_clear_pending_msg_events(),
				Some(restarted_node),
				nodes,
			);
		} else {
			nodes[remaining_node].get_and_clear_pending_msg_events();
		}
		queues.clear_link(self);
	}
}

struct NodePayments {
	pending: Vec<PaymentId>,
	resolved: HashMap<PaymentId, Option<PaymentHash>>,
}

impl NodePayments {
	fn new() -> Self {
		Self { pending: Vec::new(), resolved: new_hash_map() }
	}
}

struct PaymentTracker {
	nodes: [NodePayments; 3],
	claimed_payment_hashes: HashSet<PaymentHash>,
	payment_preimages: HashMap<PaymentHash, PaymentPreimage>,
	payment_ctr: u64,
}

impl PaymentTracker {
	fn new() -> Self {
		Self {
			nodes: [NodePayments::new(), NodePayments::new(), NodePayments::new()],
			claimed_payment_hashes: HashSet::new(),
			payment_preimages: new_hash_map(),
			payment_ctr: 0,
		}
	}

	// Returns a bool indicating whether the payment failed.
	fn check_payment_send_events(source: &ChanMan, sent_payment_id: PaymentId) -> bool {
		for payment in source.list_recent_payments() {
			match payment {
				RecentPaymentDetails::Pending { payment_id, .. }
					if payment_id == sent_payment_id =>
				{
					return true;
				},
				RecentPaymentDetails::Abandoned { payment_id, .. }
					if payment_id == sent_payment_id =>
				{
					return false;
				},
				_ => {},
			}
		}
		return false;
	}

	fn next_payment(&mut self, dest: &ChanMan) -> (PaymentSecret, PaymentHash, PaymentId) {
		self.payment_ctr += 1;
		let mut payment_preimage = PaymentPreimage([0; 32]);
		payment_preimage.0[0..8].copy_from_slice(&self.payment_ctr.to_be_bytes());
		let hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
		let secret = dest
			.create_inbound_payment_for_hash(hash, None, 3600, None, None)
			.expect("create_inbound_payment_for_hash failed");
		assert!(self.payment_preimages.insert(hash, payment_preimage).is_none());
		let mut id = PaymentId([0; 32]);
		id.0[0..8].copy_from_slice(&self.payment_ctr.to_ne_bytes());
		(secret, hash, id)
	}

	fn send(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize,
		dest_chan_id: ChannelId, amt: u64,
	) -> bool {
		let source = &nodes[source_idx];
		let dest = &nodes[dest_idx];
		let (secret, hash, id) = self.next_payment(dest);
		let (min_value_sendable, max_value_sendable, dest_scid) = source
			.list_usable_channels()
			.iter()
			.find(|chan| chan.channel_id == dest_chan_id)
			.map(|chan| {
				(
					chan.next_outbound_htlc_minimum_msat,
					chan.next_outbound_htlc_limit_msat,
					chan.short_channel_id.unwrap_or(0),
				)
			})
			.unwrap_or((0, 0, 0));
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(source.get_our_node_id(), TEST_FINAL_CLTV),
			amt,
		);
		let route = Route {
			paths: vec![Path {
				hops: vec![RouteHop {
					pubkey: dest.get_our_node_id(),
					node_features: dest.node_features(),
					short_channel_id: dest_scid,
					channel_features: dest.channel_features(),
					fee_msat: amt,
					cltv_expiry_delta: 200,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			}],
			route_params: Some(route_params.clone()),
		};
		let onion = RecipientOnionFields::secret_only(secret, amt);
		let res = source.send_payment_with_route(route, hash, onion, id);
		let succeeded = match res {
			Err(err) => {
				panic!("Errored with {:?} on initial payment send", err);
			},
			Ok(()) => {
				let expect_failure = amt < min_value_sendable || amt > max_value_sendable;
				let succeeded = Self::check_payment_send_events(source, id);
				assert_eq!(succeeded, !expect_failure);
				succeeded
			},
		};
		if succeeded {
			self.nodes[source_idx].pending.push(id);
		}
		succeeded
	}

	fn send_hop(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, middle_idx: usize,
		middle_chan_id: ChannelId, dest_idx: usize, dest_chan_id: ChannelId, amt: u64,
	) {
		let source = &nodes[source_idx];
		let middle = &nodes[middle_idx];
		let dest = &nodes[dest_idx];
		let (secret, hash, id) = self.next_payment(dest);
		let (min_value_sendable, max_value_sendable, middle_scid) = source
			.list_usable_channels()
			.iter()
			.find(|chan| chan.channel_id == middle_chan_id)
			.map(|chan| {
				(
					chan.next_outbound_htlc_minimum_msat,
					chan.next_outbound_htlc_limit_msat,
					chan.short_channel_id.unwrap_or(0),
				)
			})
			.unwrap_or((0, 0, 0));
		let dest_scid = dest
			.list_channels()
			.iter()
			.find(|chan| chan.channel_id == dest_chan_id)
			.and_then(|chan| chan.short_channel_id)
			.unwrap_or(0);
		let first_hop_fee = 50_000;
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(source.get_our_node_id(), TEST_FINAL_CLTV),
			amt,
		);
		let route = Route {
			paths: vec![Path {
				hops: vec![
					RouteHop {
						pubkey: middle.get_our_node_id(),
						node_features: middle.node_features(),
						short_channel_id: middle_scid,
						channel_features: middle.channel_features(),
						fee_msat: first_hop_fee,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: dest.get_our_node_id(),
						node_features: dest.node_features(),
						short_channel_id: dest_scid,
						channel_features: dest.channel_features(),
						fee_msat: amt,
						cltv_expiry_delta: 200,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			}],
			route_params: Some(route_params.clone()),
		};
		let onion = RecipientOnionFields::secret_only(secret, amt);
		let res = source.send_payment_with_route(route, hash, onion, id);
		let succeeded = match res {
			Err(err) => {
				panic!("Errored with {:?} on initial payment send", err);
			},
			Ok(()) => {
				let sent_amt = amt + first_hop_fee;
				let expect_failure = sent_amt < min_value_sendable || sent_amt > max_value_sendable;
				let succeeded = Self::check_payment_send_events(source, id);
				assert_eq!(succeeded, !expect_failure);
				succeeded
			},
		};
		if succeeded {
			self.nodes[source_idx].pending.push(id);
		}
	}

	fn send_noret(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize,
		dest_chan_id: ChannelId, amt: u64,
	) {
		self.send(nodes, source_idx, dest_idx, dest_chan_id, amt);
	}

	// Direct MPP payment (no hop)
	fn send_mpp_direct(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize,
		dest_chan_ids: &[ChannelId], amt: u64,
	) {
		let source = &nodes[source_idx];
		let dest = &nodes[dest_idx];
		let (secret, hash, id) = self.next_payment(dest);
		let num_paths = dest_chan_ids.len();
		if num_paths == 0 {
			return;
		}

		let amt_per_path = amt / num_paths as u64;
		let mut paths = Vec::with_capacity(num_paths);

		let dest_chans = dest.list_channels();
		let dest_scids = dest_chan_ids.iter().map(|chan_id| {
			dest_chans
				.iter()
				.find(|chan| chan.channel_id == *chan_id)
				.and_then(|chan| chan.short_channel_id)
				.unwrap()
		});

		for (i, dest_scid) in dest_scids.enumerate() {
			let path_amt = if i == num_paths - 1 {
				amt - amt_per_path * (num_paths as u64 - 1)
			} else {
				amt_per_path
			};

			paths.push(Path {
				hops: vec![RouteHop {
					pubkey: dest.get_our_node_id(),
					node_features: dest.node_features(),
					short_channel_id: dest_scid,
					channel_features: dest.channel_features(),
					fee_msat: path_amt,
					cltv_expiry_delta: 200,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			});
		}

		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(dest.get_our_node_id(), TEST_FINAL_CLTV),
			amt,
		);
		let route = Route { paths, route_params: Some(route_params) };
		let onion = RecipientOnionFields::secret_only(secret, amt);
		let res = source.send_payment_with_route(route, hash, onion, id);
		let succeeded = match res {
			Err(_) => false,
			Ok(()) => Self::check_payment_send_events(source, id),
		};
		if succeeded {
			self.nodes[source_idx].pending.push(id);
		}
	}

	// MPP payment via hop - splits payment across multiple channels on either or both hops
	fn send_mpp_hop(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, middle_idx: usize,
		middle_chan_ids: &[ChannelId], dest_idx: usize, dest_chan_ids: &[ChannelId], amt: u64,
	) {
		let source = &nodes[source_idx];
		let middle = &nodes[middle_idx];
		let dest = &nodes[dest_idx];
		let (secret, hash, id) = self.next_payment(dest);
		// Create paths by pairing middle_scids with dest_scids.
		let num_paths = middle_chan_ids.len().max(dest_chan_ids.len());
		if num_paths == 0 {
			return;
		}

		let first_hop_fee = 50_000;
		let amt_per_path = amt / num_paths as u64;
		let fee_per_path = first_hop_fee / num_paths as u64;
		let mut paths = Vec::with_capacity(num_paths);

		let middle_chans = middle.list_channels();
		let middle_scids: Vec<_> = middle_chan_ids
			.iter()
			.map(|chan_id| {
				middle_chans
					.iter()
					.find(|chan| chan.channel_id == *chan_id)
					.and_then(|chan| chan.short_channel_id)
					.unwrap()
			})
			.collect();

		let dest_chans = dest.list_channels();
		let dest_scids: Vec<_> = dest_chan_ids
			.iter()
			.map(|chan_id| {
				dest_chans
					.iter()
					.find(|chan| chan.channel_id == *chan_id)
					.and_then(|chan| chan.short_channel_id)
					.unwrap()
			})
			.collect();

		for i in 0..num_paths {
			let middle_scid = middle_scids[i % middle_scids.len()];
			let dest_scid = dest_scids[i % dest_scids.len()];

			let path_amt = if i == num_paths - 1 {
				amt - amt_per_path * (num_paths as u64 - 1)
			} else {
				amt_per_path
			};
			let path_fee = if i == num_paths - 1 {
				first_hop_fee - fee_per_path * (num_paths as u64 - 1)
			} else {
				fee_per_path
			};

			paths.push(Path {
				hops: vec![
					RouteHop {
						pubkey: middle.get_our_node_id(),
						node_features: middle.node_features(),
						short_channel_id: middle_scid,
						channel_features: middle.channel_features(),
						fee_msat: path_fee,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: dest.get_our_node_id(),
						node_features: dest.node_features(),
						short_channel_id: dest_scid,
						channel_features: dest.channel_features(),
						fee_msat: path_amt,
						cltv_expiry_delta: 200,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			});
		}

		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(dest.get_our_node_id(), TEST_FINAL_CLTV),
			amt,
		);
		let route = Route { paths, route_params: Some(route_params) };
		let onion = RecipientOnionFields::secret_only(secret, amt);
		let res = source.send_payment_with_route(route, hash, onion, id);
		let succeeded = match res {
			Err(_) => false,
			Ok(()) => Self::check_payment_send_events(source, id),
		};
		if succeeded {
			self.nodes[source_idx].pending.push(id);
		}
	}

	fn claim_payment(&mut self, node: &HarnessNode<'_>, payment_hash: PaymentHash, fail: bool) {
		if fail {
			node.fail_htlc_backwards(&payment_hash);
		} else {
			let payment_preimage = *self
				.payment_preimages
				.get(&payment_hash)
				.expect("PaymentClaimable for unknown payment hash");
			node.claim_funds(payment_preimage);
			self.claimed_payment_hashes.insert(payment_hash);
		}
	}

	fn mark_sent(&mut self, node_idx: usize, sent_id: PaymentId, payment_hash: PaymentHash) {
		let node = &mut self.nodes[node_idx];
		let idx_opt = node.pending.iter().position(|id| *id == sent_id);
		if let Some(idx) = idx_opt {
			node.pending.remove(idx);
			node.resolved.insert(sent_id, Some(payment_hash));
		} else {
			assert!(node.resolved.contains_key(&sent_id));
		}
	}

	fn mark_resolved_without_hash(&mut self, node_idx: usize, payment_id: PaymentId) {
		let node = &mut self.nodes[node_idx];
		let idx_opt = node.pending.iter().position(|id| *id == payment_id);
		if let Some(idx) = idx_opt {
			node.pending.remove(idx);
			node.resolved.insert(payment_id, None);
		} else if !node.resolved.contains_key(&payment_id) {
			// Some resolutions can arrive immediately, before the send helper records
			// the payment as pending. Track them so later duplicate events are accepted.
			node.resolved.insert(payment_id, None);
		}
	}

	fn mark_successful_probe(&mut self, node_idx: usize, payment_id: PaymentId) {
		let node = &mut self.nodes[node_idx];
		let idx_opt = node.pending.iter().position(|id| *id == payment_id);
		if let Some(idx) = idx_opt {
			node.pending.remove(idx);
			node.resolved.insert(payment_id, None);
		} else {
			assert!(node.resolved.contains_key(&payment_id));
		}
	}

	fn assert_all_resolved(&self) {
		for (idx, node) in self.nodes.iter().enumerate() {
			assert!(
				node.pending.is_empty(),
				"Node {} has {} stuck pending payments after settling all state",
				idx,
				node.pending.len()
			);
		}
	}

	fn assert_claims_reported(&self) {
		for hash in self.claimed_payment_hashes.iter() {
			let found = self
				.nodes
				.iter()
				.any(|node| node.resolved.values().any(|h| h.as_ref() == Some(hash)));
			assert!(
				found,
				"Payment {:?} was claimed by receiver but sender never got PaymentSent",
				hash
			);
		}
	}
}

struct Harness<'a, Out: Output + MaybeSend + MaybeSync> {
	out: Out,
	chan_type: ChanType,
	chain_state: ChainState,
	nodes: [HarnessNode<'a>; 3],
	ab_link: PeerLink,
	bc_link: PeerLink,
	queues: EventQueues,
	payments: PaymentTracker,
}

fn build_node_config(chan_type: ChanType) -> UserConfig {
	let mut config = UserConfig::default();
	config.channel_config.forwarding_fee_proportional_millionths = 0;
	config.channel_handshake_config.announce_for_forwarding = true;
	config.reject_inbound_splices = false;
	match chan_type {
		ChanType::Legacy => {
			config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
			config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = false;
		},
		ChanType::KeyedAnchors => {
			config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
			config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = false;
		},
		ChanType::ZeroFeeCommitments => {
			config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
			config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
		},
	}
	config
}

fn assert_test_invariants(nodes: &[HarnessNode<'_>; 3]) {
	assert_eq!(nodes[0].list_channels().len(), 3);
	assert_eq!(nodes[1].list_channels().len(), 6);
	assert_eq!(nodes[2].list_channels().len(), 3);

	// All broadcasters should be empty. Broadcast transactions are handled explicitly.
	assert!(nodes[0].broadcaster.txn_broadcasted.borrow().is_empty());
	assert!(nodes[1].broadcaster.txn_broadcasted.borrow().is_empty());
	assert!(nodes[2].broadcaster.txn_broadcasted.borrow().is_empty());
}

fn connect_peers(source: &ChanMan<'_>, dest: &ChanMan<'_>) {
	let init_dest =
		Init { features: dest.init_features(), networks: None, remote_network_address: None };
	source.peer_connected(dest.get_our_node_id(), &init_dest, true).unwrap();
	let init_src =
		Init { features: source.init_features(), networks: None, remote_network_address: None };
	dest.peer_connected(source.get_our_node_id(), &init_src, false).unwrap();
}

fn make_channel(
	source: &HarnessNode<'_>, dest: &HarnessNode<'_>, chan_id: i32, trusted_open: bool,
	trusted_accept: bool, chain_state: &mut ChainState,
) {
	if trusted_open {
		source
			.create_channel_to_trusted_peer_0reserve(
				dest.get_our_node_id(),
				100_000,
				42,
				0,
				None,
				None,
			)
			.unwrap();
	} else {
		source.create_channel(dest.get_our_node_id(), 100_000, 42, 0, None, None).unwrap();
	}
	let open_channel = {
		let events = source.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::SendOpenChannel { ref msg, .. } = events[0] {
			msg.clone()
		} else {
			panic!("Wrong event type");
		}
	};

	dest.handle_open_channel(source.get_our_node_id(), &open_channel);
	let accept_channel = {
		let events = dest.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		if let events::Event::OpenChannelRequest {
			ref temporary_channel_id,
			ref counterparty_node_id,
			..
		} = events[0]
		{
			let mut random_bytes = [0u8; 16];
			random_bytes.copy_from_slice(&dest.keys_manager.get_secure_random_bytes()[..16]);
			let user_channel_id = u128::from_be_bytes(random_bytes);
			if trusted_accept {
				dest.accept_inbound_channel_from_trusted_peer(
					temporary_channel_id,
					counterparty_node_id,
					user_channel_id,
					TrustedChannelFeatures::ZeroReserve,
					None,
				)
				.unwrap();
			} else {
				dest.accept_inbound_channel(
					temporary_channel_id,
					counterparty_node_id,
					user_channel_id,
					None,
				)
				.unwrap();
			}
		} else {
			panic!("Wrong event type");
		}
		let events = dest.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::SendAcceptChannel { ref msg, .. } = events[0] {
			msg.clone()
		} else {
			panic!("Wrong event type");
		}
	};

	source.handle_accept_channel(dest.get_our_node_id(), &accept_channel);
	{
		let mut events = source.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		if let events::Event::FundingGenerationReady {
			temporary_channel_id,
			channel_value_satoshis,
			output_script,
			..
		} = events.pop().unwrap()
		{
			let tx = Transaction {
				version: Version(chan_id),
				lock_time: LockTime::ZERO,
				input: Vec::new(),
				output: vec![TxOut {
					value: Amount::from_sat(channel_value_satoshis),
					script_pubkey: output_script,
				}],
			};
			source
				.funding_transaction_generated(
					temporary_channel_id,
					dest.get_our_node_id(),
					tx.clone(),
				)
				.unwrap();
			chain_state.confirm_tx(tx);
		} else {
			panic!("Wrong event type");
		}
	}

	let funding_created = {
		let events = source.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::SendFundingCreated { ref msg, .. } = events[0] {
			msg.clone()
		} else {
			panic!("Wrong event type");
		}
	};
	dest.handle_funding_created(source.get_our_node_id(), &funding_created);
	// Complete any pending monitor persistence callbacks for dest after watch_channel.
	dest.complete_all_pending_monitor_updates();

	let (funding_signed, channel_id) = {
		let events = dest.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::SendFundingSigned { ref msg, .. } = events[0] {
			(msg.clone(), msg.channel_id)
		} else {
			panic!("Wrong event type");
		}
	};
	let events = dest.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	if let events::Event::ChannelPending { ref counterparty_node_id, .. } = events[0] {
		assert_eq!(counterparty_node_id, &source.get_our_node_id());
	} else {
		panic!("Wrong event type");
	}

	source.handle_funding_signed(dest.get_our_node_id(), &funding_signed);
	// Complete any pending monitor persistence callbacks for source after watch_channel.
	source.complete_all_pending_monitor_updates();

	let events = source.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	if let events::Event::ChannelPending {
		ref counterparty_node_id,
		channel_id: ref event_channel_id,
		..
	} = events[0]
	{
		assert_eq!(counterparty_node_id, &dest.get_our_node_id());
		assert_eq!(*event_channel_id, channel_id);
	} else {
		panic!("Wrong event type");
	}
}

fn lock_fundings(nodes: &[HarnessNode<'_>; 3]) {
	let mut node_events = Vec::new();
	for node in nodes.iter() {
		node_events.push(node.get_and_clear_pending_msg_events());
	}
	for (idx, node_event) in node_events.iter().enumerate() {
		for event in node_event {
			if let MessageSendEvent::SendChannelReady { ref node_id, ref msg } = event {
				for node in nodes.iter() {
					if node.get_our_node_id() == *node_id {
						node.handle_channel_ready(nodes[idx].get_our_node_id(), msg);
					}
				}
			} else {
				panic!("Wrong event type");
			}
		}
	}

	for node in nodes.iter() {
		let events = node.get_and_clear_pending_msg_events();
		for event in events {
			if let MessageSendEvent::SendAnnouncementSignatures { .. } = event {
			} else {
				panic!("Wrong event type");
			}
		}
	}
}

impl<'a, Out: Output + MaybeSend + MaybeSync> Harness<'a, Out> {
	fn new(config_byte: u8, out: Out, router: &'a FuzzRouter) -> Self {
		let chan_type = match (config_byte >> 3) & 0b11 {
			0 => ChanType::Legacy,
			1 => ChanType::KeyedAnchors,
			_ => ChanType::ZeroFeeCommitments,
		};
		let persistence_styles = [
			if config_byte & 0b01 != 0 {
				ChannelMonitorUpdateStatus::InProgress
			} else {
				ChannelMonitorUpdateStatus::Completed
			},
			if config_byte & 0b10 != 0 {
				ChannelMonitorUpdateStatus::InProgress
			} else {
				ChannelMonitorUpdateStatus::Completed
			},
			if config_byte & 0b100 != 0 {
				ChannelMonitorUpdateStatus::InProgress
			} else {
				ChannelMonitorUpdateStatus::Completed
			},
		];
		let wallet_a = TestWalletSource::new(SecretKey::from_slice(&[1; 32]).unwrap());
		let wallet_b = TestWalletSource::new(SecretKey::from_slice(&[2; 32]).unwrap());
		let wallet_c = TestWalletSource::new(SecretKey::from_slice(&[3; 32]).unwrap());
		let wallets = [&wallet_a, &wallet_b, &wallet_c];
		let coinbase_tx = bitcoin::Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn { ..Default::default() }],
			output: wallets
				.iter()
				.map(|wallet| TxOut {
					value: Amount::from_sat(100_000),
					script_pubkey: wallet.get_change_script().unwrap(),
				})
				.collect(),
		};
		for (idx, wallet) in wallets.iter().enumerate() {
			wallet.add_utxo(coinbase_tx.clone(), idx as u32);
		}

		let fee_est_a = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
		let fee_est_b = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
		let fee_est_c = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
		let broadcast_a = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });
		let broadcast_b = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });
		let broadcast_c = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });

		// 3 nodes is enough to hit all the possible cases, notably
		// unknown-source-unknown-dest forwarding.
		let mut nodes = [
			HarnessNode::new(
				0,
				wallet_a,
				Arc::clone(&fee_est_a),
				Arc::clone(&broadcast_a),
				persistence_styles[0],
				&out,
				router,
				chan_type,
			),
			HarnessNode::new(
				1,
				wallet_b,
				Arc::clone(&fee_est_b),
				Arc::clone(&broadcast_b),
				persistence_styles[1],
				&out,
				router,
				chan_type,
			),
			HarnessNode::new(
				2,
				wallet_c,
				Arc::clone(&fee_est_c),
				Arc::clone(&broadcast_c),
				persistence_styles[2],
				&out,
				router,
				chan_type,
			),
		];
		let mut chain_state = ChainState::new();

		// Connect peers first, then create channels.
		connect_peers(&nodes[0], &nodes[1]);
		connect_peers(&nodes[1], &nodes[2]);

		let set_0reserve = chan_type != ChanType::Legacy;
		// Create 3 channels between A-B and 3 channels between B-C (6 total).
		//
		// Use distinct version numbers for each funding transaction so each test
		// channel gets its own txid and funding outpoint.
		// A-B: channel 2 A and B have 0-reserve (trusted open + trusted accept),
		//      channel 3 A has 0-reserve (trusted accept), if channels are non-legacy.
		make_channel(&nodes[0], &nodes[1], 1, false, false, &mut chain_state);
		make_channel(&nodes[0], &nodes[1], 2, set_0reserve, set_0reserve, &mut chain_state);
		make_channel(&nodes[0], &nodes[1], 3, false, set_0reserve, &mut chain_state);
		// B-C: channel 4 B has 0-reserve (via trusted accept),
		//      channel 5 C has 0-reserve (via trusted open), if channels are non-legacy.
		make_channel(&nodes[1], &nodes[2], 4, false, set_0reserve, &mut chain_state);
		make_channel(&nodes[1], &nodes[2], 5, set_0reserve, false, &mut chain_state);
		make_channel(&nodes[1], &nodes[2], 6, false, false, &mut chain_state);

		// Wipe the transactions-broadcasted set to make sure we don't broadcast
		// any transactions during normal operation after setup.
		nodes[0].broadcaster.txn_broadcasted.borrow_mut().clear();
		nodes[1].broadcaster.txn_broadcasted.borrow_mut().clear();
		nodes[2].broadcaster.txn_broadcasted.borrow_mut().clear();

		// Sync all nodes to tip to lock the funding.
		nodes[0].sync_with_chain_state(&chain_state, None);
		nodes[1].sync_with_chain_state(&chain_state, None);
		nodes[2].sync_with_chain_state(&chain_state, None);

		lock_fundings(&nodes);

		let chan_ab_ids = {
			// Get channel IDs for all A-B channels (from node A's perspective).
			let node_a_chans = nodes[0].list_usable_channels();
			[node_a_chans[0].channel_id, node_a_chans[1].channel_id, node_a_chans[2].channel_id]
		};
		let chan_bc_ids = {
			// Get channel IDs for all B-C channels (from node C's perspective).
			let node_c_chans = nodes[2].list_usable_channels();
			[node_c_chans[0].channel_id, node_c_chans[1].channel_id, node_c_chans[2].channel_id]
		};

		for node in &mut nodes {
			node.serialized_manager = node.encode();
		}

		Self {
			out,
			chan_type,
			chain_state,
			nodes,
			ab_link: PeerLink::new(0, 1, chan_ab_ids),
			bc_link: PeerLink::new(1, 2, chan_bc_ids),
			queues: EventQueues::new(),
			payments: PaymentTracker::new(),
		}
	}

	fn chan_a_id(&self) -> ChannelId {
		self.ab_link.first_channel_id()
	}

	fn chan_b_id(&self) -> ChannelId {
		self.bc_link.first_channel_id()
	}

	fn finish(&self) {
		assert_test_invariants(&self.nodes);
	}

	fn link_between(&self, source_idx: usize, dest_idx: usize) -> &PeerLink {
		if self.ab_link.connects(source_idx, dest_idx) {
			&self.ab_link
		} else if self.bc_link.connects(source_idx, dest_idx) {
			&self.bc_link
		} else {
			panic!("invalid payment peers")
		}
	}

	fn channel_ids_between(&self, source_idx: usize, dest_idx: usize) -> [ChannelId; 3] {
		self.link_between(source_idx, dest_idx).channel_ids().clone()
	}

	fn first_channel_id_between(&self, source_idx: usize, dest_idx: usize) -> ChannelId {
		self.link_between(source_idx, dest_idx).first_channel_id()
	}

	fn send_on_channel(
		&mut self, source_idx: usize, dest_idx: usize, dest_chan_id: ChannelId, amt: u64,
	) -> bool {
		self.payments.send(&self.nodes, source_idx, dest_idx, dest_chan_id, amt)
	}

	fn send(&mut self, source_idx: usize, dest_idx: usize, amt: u64) {
		let dest_chan_id = self.first_channel_id_between(source_idx, dest_idx);
		self.payments.send_noret(&self.nodes, source_idx, dest_idx, dest_chan_id, amt);
	}

	fn send_hop(&mut self, source_idx: usize, middle_idx: usize, dest_idx: usize, amt: u64) {
		let middle_chan_id = self.first_channel_id_between(source_idx, middle_idx);
		let dest_chan_id = self.first_channel_id_between(middle_idx, dest_idx);
		self.payments.send_hop(
			&self.nodes,
			source_idx,
			middle_idx,
			middle_chan_id,
			dest_idx,
			dest_chan_id,
			amt,
		);
	}

	fn send_mpp_direct(
		&mut self, source_idx: usize, dest_idx: usize, channels: MppDirectChannels, amt: u64,
	) {
		match channels {
			MppDirectChannels::All => {
				let dest_chan_ids = self.channel_ids_between(source_idx, dest_idx);
				self.payments.send_mpp_direct(
					&self.nodes,
					source_idx,
					dest_idx,
					&dest_chan_ids,
					amt,
				);
			},
			MppDirectChannels::RepeatedFirst => {
				let dest_chan_id = self.first_channel_id_between(source_idx, dest_idx);
				let dest_chan_ids = [dest_chan_id, dest_chan_id, dest_chan_id];
				self.payments.send_mpp_direct(
					&self.nodes,
					source_idx,
					dest_idx,
					&dest_chan_ids,
					amt,
				);
			},
		}
	}

	fn send_mpp_hop(
		&mut self, source_idx: usize, middle_idx: usize, dest_idx: usize, channels: MppHopChannels,
		amt: u64,
	) {
		let middle_chan_ids = self.channel_ids_between(source_idx, middle_idx);
		let dest_chan_ids = self.channel_ids_between(middle_idx, dest_idx);
		let middle_first_chan_id = middle_chan_ids[0];
		let dest_first_chan_id = dest_chan_ids[0];
		match channels {
			MppHopChannels::FirstHop => {
				let dest_chan_ids = [dest_first_chan_id];
				self.payments.send_mpp_hop(
					&self.nodes,
					source_idx,
					middle_idx,
					&middle_chan_ids,
					dest_idx,
					&dest_chan_ids,
					amt,
				);
			},
			MppHopChannels::BothHops => {
				self.payments.send_mpp_hop(
					&self.nodes,
					source_idx,
					middle_idx,
					&middle_chan_ids,
					dest_idx,
					&dest_chan_ids,
					amt,
				);
			},
			MppHopChannels::SecondHop => {
				let middle_chan_ids = [middle_first_chan_id];
				self.payments.send_mpp_hop(
					&self.nodes,
					source_idx,
					middle_idx,
					&middle_chan_ids,
					dest_idx,
					&dest_chan_ids,
					amt,
				);
			},
		}
	}

	fn process_msg_events(
		&mut self, node_idx: usize, corrupt_forward: bool, limit_events: ProcessMessages,
	) -> bool {
		fn find_destination_node(nodes: &[HarnessNode<'_>; 3], node_id: &PublicKey) -> usize {
			nodes
				.iter()
				.position(|node| node.get_our_node_id() == *node_id)
				.expect("message destination should be a known harness node")
		}

		fn log_msg_delivery<Out: Output + MaybeSend + MaybeSync>(
			node_idx: usize, dest_idx: usize, msg_name: &str, out: &Out,
		) {
			out.locked_write(
				format!("Delivering {} from node {} to node {}.\n", msg_name, node_idx, dest_idx)
					.as_bytes(),
			);
		}

		fn log_peer_message<Out: Output + MaybeSend + MaybeSync>(
			node_idx: usize, node_id: &PublicKey, nodes: &[HarnessNode<'_>; 3], out: &Out,
			msg_name: &str,
		) -> usize {
			let dest_idx = find_destination_node(nodes, node_id);
			log_msg_delivery(node_idx, dest_idx, msg_name, out);
			dest_idx
		}

		fn handle_update_add_htlc(
			source_node_id: PublicKey, dest: &HarnessNode<'_>, update_add: &UpdateAddHTLC,
			corrupt_forward: bool,
		) {
			if !corrupt_forward {
				dest.handle_update_add_htlc(source_node_id, update_add);
			} else {
				// Corrupt the update_add_htlc message so that its HMAC check will fail and we
				// generate an update_fail_malformed_htlc instead of an update_fail_htlc as we do
				// when we reject a payment.
				let mut msg_ser = update_add.encode();
				msg_ser[1000] ^= 0xff;
				let new_msg =
					UpdateAddHTLC::read_from_fixed_length_buffer(&mut &msg_ser[..]).unwrap();
				dest.handle_update_add_htlc(source_node_id, &new_msg);
			}
		}

		fn handle_update_htlcs_event<Out: Output + MaybeSend + MaybeSync>(
			node_idx: usize, source_node_id: PublicKey, node_id: PublicKey, channel_id: ChannelId,
			updates: CommitmentUpdate, corrupt_forward: bool, limit_events: ProcessMessages,
			nodes: &[HarnessNode<'_>; 3], out: &Out,
		) -> Option<MessageSendEvent> {
			let dest_idx = find_destination_node(nodes, &node_id);
			let dest = &nodes[dest_idx];
			let CommitmentUpdate {
				update_add_htlcs,
				update_fail_htlcs,
				update_fulfill_htlcs,
				update_fail_malformed_htlcs,
				update_fee,
				commitment_signed,
			} = updates;

			for update_add in update_add_htlcs.iter() {
				log_msg_delivery(node_idx, dest_idx, "update_add_htlc", out);
				handle_update_add_htlc(source_node_id, dest, update_add, corrupt_forward);
			}
			let processed_change = !update_add_htlcs.is_empty()
				|| !update_fulfill_htlcs.is_empty()
				|| !update_fail_htlcs.is_empty()
				|| !update_fail_malformed_htlcs.is_empty();
			for update_fulfill in update_fulfill_htlcs {
				log_msg_delivery(node_idx, dest_idx, "update_fulfill_htlc", out);
				dest.handle_update_fulfill_htlc(source_node_id, update_fulfill);
			}
			for update_fail in update_fail_htlcs.iter() {
				log_msg_delivery(node_idx, dest_idx, "update_fail_htlc", out);
				dest.handle_update_fail_htlc(source_node_id, update_fail);
			}
			for update_fail_malformed in update_fail_malformed_htlcs.iter() {
				log_msg_delivery(node_idx, dest_idx, "update_fail_malformed_htlc", out);
				dest.handle_update_fail_malformed_htlc(source_node_id, update_fail_malformed);
			}
			if let Some(msg) = update_fee {
				log_msg_delivery(node_idx, dest_idx, "update_fee", out);
				dest.handle_update_fee(source_node_id, &msg);
			}
			if limit_events != ProcessMessages::AllMessages && processed_change {
				// If we only want to process some messages, don't deliver the CS until later.
				return Some(MessageSendEvent::UpdateHTLCs {
					node_id,
					channel_id,
					updates: CommitmentUpdate {
						update_add_htlcs: Vec::new(),
						update_fail_htlcs: Vec::new(),
						update_fulfill_htlcs: Vec::new(),
						update_fail_malformed_htlcs: Vec::new(),
						update_fee: None,
						commitment_signed,
					},
				});
			}
			log_msg_delivery(node_idx, dest_idx, "commitment_signed", out);
			dest.handle_commitment_signed_batch_test(source_node_id, &commitment_signed);
			None
		}

		fn process_msg_event<Out: Output + MaybeSend + MaybeSync>(
			node_idx: usize, source_node_id: PublicKey, event: MessageSendEvent,
			corrupt_forward: bool, limit_events: ProcessMessages, nodes: &[HarnessNode<'_>; 3],
			out: &Out,
		) -> Option<MessageSendEvent> {
			match event {
				MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates } => {
					handle_update_htlcs_event(
						node_idx,
						source_node_id,
						node_id,
						channel_id,
						updates,
						corrupt_forward,
						limit_events,
						nodes,
						out,
					)
				},
				MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
					let dest_idx =
						log_peer_message(node_idx, node_id, nodes, out, "revoke_and_ack");
					nodes[dest_idx].handle_revoke_and_ack(source_node_id, msg);
					None
				},
				MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
					let dest_idx =
						log_peer_message(node_idx, node_id, nodes, out, "channel_reestablish");
					nodes[dest_idx].handle_channel_reestablish(source_node_id, msg);
					None
				},
				MessageSendEvent::SendStfu { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "stfu");
					nodes[dest_idx].handle_stfu(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxAddInput { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_add_input");
					nodes[dest_idx].handle_tx_add_input(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxAddOutput { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_add_output");
					nodes[dest_idx].handle_tx_add_output(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxRemoveInput { ref node_id, ref msg } => {
					let dest_idx =
						log_peer_message(node_idx, node_id, nodes, out, "tx_remove_input");
					nodes[dest_idx].handle_tx_remove_input(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxRemoveOutput { ref node_id, ref msg } => {
					let dest_idx =
						log_peer_message(node_idx, node_id, nodes, out, "tx_remove_output");
					nodes[dest_idx].handle_tx_remove_output(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_complete");
					nodes[dest_idx].handle_tx_complete(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxAbort { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_abort");
					nodes[dest_idx].handle_tx_abort(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxInitRbf { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_init_rbf");
					nodes[dest_idx].handle_tx_init_rbf(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxAckRbf { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_ack_rbf");
					nodes[dest_idx].handle_tx_ack_rbf(source_node_id, msg);
					None
				},
				MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "tx_signatures");
					nodes[dest_idx].handle_tx_signatures(source_node_id, msg);
					None
				},
				MessageSendEvent::SendSpliceInit { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "splice_init");
					nodes[dest_idx].handle_splice_init(source_node_id, msg);
					None
				},
				MessageSendEvent::SendSpliceAck { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "splice_ack");
					nodes[dest_idx].handle_splice_ack(source_node_id, msg);
					None
				},
				MessageSendEvent::SendSpliceLocked { ref node_id, ref msg } => {
					let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "splice_locked");
					nodes[dest_idx].handle_splice_locked(source_node_id, msg);
					None
				},
				MessageSendEvent::HandleError { ref action, .. } => {
					assert_action_timeout_awaiting_response(action);
					None
				},
				MessageSendEvent::SendChannelReady { .. }
				| MessageSendEvent::SendAnnouncementSignatures { .. }
				| MessageSendEvent::SendChannelUpdate { .. } => {
					// Can be generated as a reestablish response.
					None
				},
				MessageSendEvent::BroadcastChannelUpdate { .. } => {
					// Can be generated as a result of calling `timer_tick_occurred` enough
					// times while peers are disconnected.
					None
				},
				_ => panic!("Unhandled message event {:?}", event),
			}
		}

		let nodes = &self.nodes;
		let out = &self.out;
		let queues = &mut self.queues;
		let mut events = queues.take_for_node(node_idx);
		let mut new_events = Vec::new();
		if limit_events != ProcessMessages::OnePendingMessage {
			new_events = nodes[node_idx].get_and_clear_pending_msg_events();
		}
		let mut had_events = false;
		let source_node_id = nodes[node_idx].get_our_node_id();
		let mut events_iter = events.drain(..).chain(new_events.drain(..));
		let mut extra_ev = None;
		for event in &mut events_iter {
			had_events = true;
			extra_ev = process_msg_event(
				node_idx,
				source_node_id,
				event,
				corrupt_forward,
				limit_events,
				nodes,
				out,
			);
			if limit_events != ProcessMessages::AllMessages {
				break;
			}
		}
		if node_idx == 1 {
			let remaining = extra_ev.into_iter().chain(events_iter).collect::<Vec<_>>();
			queues.route_from_middle(remaining, None, nodes);
		} else if node_idx == 0 {
			if let Some(ev) = extra_ev {
				queues.push_for_node(0, ev);
			}
			queues.extend_for_node(0, events_iter);
		} else {
			if let Some(ev) = extra_ev {
				queues.push_for_node(2, ev);
			}
			queues.extend_for_node(2, events_iter);
		}
		had_events
	}

	fn process_events(&mut self, node_idx: usize, fail: bool) -> bool {
		let nodes = &self.nodes;
		let chain_state = &mut self.chain_state;
		let payments = &mut self.payments;
		// Multiple HTLCs can resolve for the same payment hash, so deduplicate
		// claim/fail handling per event batch.
		let mut claim_set = new_hash_map();
		let mut events = nodes[node_idx].get_and_clear_pending_events();
		let mut had_events = !events.is_empty();
		for event in events.drain(..) {
			match event {
				events::Event::PaymentClaimable { payment_hash, .. } => {
					if claim_set.insert(payment_hash.0, ()).is_none() {
						payments.claim_payment(&nodes[node_idx], payment_hash, fail);
					}
				},
				events::Event::PaymentSent { payment_id, payment_hash, .. } => {
					payments.mark_sent(node_idx, payment_id.unwrap(), payment_hash);
				},
				// Even though we don't explicitly send probes, because probes are detected based on
				// hashing the payment hash+preimage, it is rather trivial for the fuzzer to build
				// payments that accidentally end up looking like probes.
				events::Event::ProbeSuccessful { payment_id, .. } => {
					payments.mark_successful_probe(node_idx, payment_id);
				},
				events::Event::PaymentFailed { payment_id, .. }
				| events::Event::ProbeFailed { payment_id, .. } => {
					payments.mark_resolved_without_hash(node_idx, payment_id);
				},
				events::Event::PaymentClaimed { .. } => {},
				events::Event::PaymentPathSuccessful { .. } => {},
				events::Event::PaymentPathFailed { .. } => {},
				events::Event::PaymentForwarded { .. } if node_idx == 1 => {},
				events::Event::ChannelReady { .. } => {},
				events::Event::HTLCHandlingFailed { .. } => {},
				events::Event::FundingTransactionReadyForSigning {
					channel_id,
					counterparty_node_id,
					unsigned_transaction,
					..
				} => {
					let signed_tx = nodes[node_idx].wallet.sign_tx(unsigned_transaction).unwrap();
					nodes[node_idx]
						.funding_transaction_signed(&channel_id, &counterparty_node_id, signed_tx)
						.unwrap();
				},
				events::Event::SpliceNegotiated { new_funding_txo, .. } => {
					let mut txs = nodes[node_idx].broadcaster.txn_broadcasted.borrow_mut();
					assert!(txs.len() >= 1);
					let splice_tx = txs.remove(0);
					assert_eq!(new_funding_txo.txid, splice_tx.compute_txid());
					chain_state.add_pending_tx(splice_tx);
				},
				events::Event::SpliceNegotiationFailed { .. } => {},
				events::Event::DiscardFunding {
					funding_info:
						events::FundingInfo::Contribution { .. } | events::FundingInfo::Tx { .. },
					..
				} => {},
				_ => panic!("Unhandled event: {:?}", event),
			}
		}
		while nodes[node_idx].needs_pending_htlc_processing() {
			nodes[node_idx].process_pending_htlc_forwards();
			had_events = true;
		}
		had_events
	}

	fn process_msg_noret(
		&mut self, node_idx: usize, corrupt_forward: bool, limit_events: ProcessMessages,
	) {
		self.process_msg_events(node_idx, corrupt_forward, limit_events);
	}

	fn process_ev_noret(&mut self, node_idx: usize, fail: bool) {
		self.process_events(node_idx, fail);
	}

	fn process_all_events(&mut self) {
		let mut last_pass_no_updates = false;
		for i in 0..std::usize::MAX {
			if i == 100 {
				panic!(
					"It may take may iterations to settle the state, but it should not take forever"
				);
			}
			let mut made_progress = self.refresh_serialized_managers();
			// Next, make sure no monitor completion callbacks are pending.
			made_progress |= self.ab_link.complete_all_monitor_updates(&self.nodes);
			made_progress |= self.bc_link.complete_all_monitor_updates(&self.nodes);
			// Then, make sure any current forwards make their way to their destination.
			if self.process_msg_events(0, false, ProcessMessages::AllMessages) {
				last_pass_no_updates = false;
				continue;
			}
			if self.process_msg_events(1, false, ProcessMessages::AllMessages) {
				last_pass_no_updates = false;
				continue;
			}
			if self.process_msg_events(2, false, ProcessMessages::AllMessages) {
				last_pass_no_updates = false;
				continue;
			}
			// ...making sure any payments are claimed.
			if self.process_events(0, false) {
				last_pass_no_updates = false;
				continue;
			}
			if self.process_events(1, false) {
				last_pass_no_updates = false;
				continue;
			}
			if self.process_events(2, false) {
				last_pass_no_updates = false;
				continue;
			}
			if made_progress {
				last_pass_no_updates = false;
				continue;
			}
			if last_pass_no_updates {
				// In some cases, we may generate a message to send in
				// `process_msg_events`, but block sending until
				// `complete_all_monitor_updates` gets called on the next
				// iteration.
				//
				// Thus, we only exit if we manage two iterations with no messages
				// or events to process.
				break;
			}
			last_pass_no_updates = true;
		}
	}

	fn disconnect_ab(&mut self) {
		self.ab_link.disconnect(&self.nodes, &mut self.queues);
	}

	fn disconnect_bc(&mut self) {
		self.bc_link.disconnect(&self.nodes, &mut self.queues);
	}

	fn reconnect_ab(&mut self) {
		self.ab_link.reconnect(&self.nodes);
	}

	fn reconnect_bc(&mut self) {
		self.bc_link.reconnect(&self.nodes);
	}

	fn restart_node(&mut self, node_idx: usize, v: u8, router: &'a FuzzRouter) {
		match node_idx {
			0 => {
				self.ab_link.disconnect_for_reload(0, &self.nodes, &mut self.queues);
			},
			1 => {
				self.ab_link.disconnect_for_reload(1, &self.nodes, &mut self.queues);
				self.bc_link.disconnect_for_reload(1, &self.nodes, &mut self.queues);
			},
			2 => {
				self.bc_link.disconnect_for_reload(2, &self.nodes, &mut self.queues);
			},
			_ => panic!("invalid node index"),
		}
		self.nodes[node_idx].reload(v, &self.out, router, self.chan_type);
	}

	fn settle_all(&mut self) {
		// First, make sure peers are all connected to each other
		self.reconnect_ab();
		self.reconnect_bc();

		for op in SUPPORTED_SIGNER_OPS {
			self.nodes[0].keys_manager.enable_op_for_all_signers(op);
			self.nodes[1].keys_manager.enable_op_for_all_signers(op);
			self.nodes[2].keys_manager.enable_op_for_all_signers(op);
		}
		self.nodes[0].signer_unblocked(None);
		self.nodes[1].signer_unblocked(None);
		self.nodes[2].signer_unblocked(None);

		self.process_all_events();

		// Since MPP payments are supported, we wait until we fully settle the state of all
		// channels to see if we have any committed HTLC parts of an MPP payment that need
		// to be failed back.
		for node in self.nodes.iter() {
			node.timer_tick_occurred();
		}
		self.process_all_events();

		// Verify no payments are stuck - all should have resolved
		self.payments.assert_all_resolved();
		// Verify that every payment claimed by a receiver resulted in a
		// PaymentSent event at the sender.
		self.payments.assert_claims_reported();

		// All HTLCs should have been claimed or failed once we reach quiescence.
		for (idx, node) in self.nodes.iter().enumerate() {
			for chan in node.list_channels() {
				assert!(
					chan.pending_inbound_htlcs.is_empty() && chan.pending_outbound_htlcs.is_empty(),
					"Node {} channel {:?} has stuck HTLCs after settling all state: \
					 {} inbound {:?}, {} outbound {:?}",
					idx,
					chan.channel_id,
					chan.pending_inbound_htlcs.len(),
					chan.pending_inbound_htlcs,
					chan.pending_outbound_htlcs.len(),
					chan.pending_outbound_htlcs
				);
			}
		}

		// Finally, make sure that at least one end of each channel can make a substantial payment.
		let chan_ab_ids = self.ab_link.channel_ids().clone();
		let chan_bc_ids = self.bc_link.channel_ids().clone();
		for chan_id in chan_ab_ids {
			assert!(
				self.send_on_channel(0, 1, chan_id, 10_000_000)
					|| self.send_on_channel(1, 0, chan_id, 10_000_000)
			);
		}
		for chan_id in chan_bc_ids {
			assert!(
				self.send_on_channel(1, 2, chan_id, 10_000_000)
					|| self.send_on_channel(2, 1, chan_id, 10_000_000)
			);
		}

		self.nodes[0].record_last_htlc_clear_fee();
		self.nodes[1].record_last_htlc_clear_fee();
		self.nodes[2].record_last_htlc_clear_fee();
	}

	fn refresh_serialized_managers(&mut self) -> bool {
		let mut made_progress = false;
		for node in &mut self.nodes {
			made_progress |= node.refresh_serialized_manager();
		}
		made_progress
	}
}

#[inline]
pub fn do_test<Out: Output + MaybeSend + MaybeSync>(data: &[u8], out: Out) {
	let router = FuzzRouter {};
	// Read initial monitor styles and channel type from fuzz input byte 0:
	// bits 0-2: monitor styles (1 bit per node)
	// bits 3-4: channel type (0=Legacy, 1=KeyedAnchors, 2=ZeroFeeCommitments)
	let config_byte = if !data.is_empty() { data[0] } else { 0 };
	let mut harness = Harness::new(config_byte, out, &router);
	let mut read_pos = 1; // First byte was consumed for initial config.

	'fuzz_loop: loop {
		if data.len() < read_pos + 1 {
			break 'fuzz_loop;
		}
		let v = data[read_pos];
		read_pos += 1;
		harness
			.out
			.locked_write(format!("READ A BYTE! HANDLING INPUT {:x}...........\n", v).as_bytes());
		match v {
			// In general, we keep related message groups close together in binary form, allowing
			// bit-twiddling mutations to have similar effects. This is probably overkill, but no
			// harm in doing so.
			0x00 => harness.nodes[0].set_persistence_style(ChannelMonitorUpdateStatus::InProgress),
			0x01 => harness.nodes[1].set_persistence_style(ChannelMonitorUpdateStatus::InProgress),
			0x02 => harness.nodes[2].set_persistence_style(ChannelMonitorUpdateStatus::InProgress),
			0x04 => harness.nodes[0].set_persistence_style(ChannelMonitorUpdateStatus::Completed),
			0x05 => harness.nodes[1].set_persistence_style(ChannelMonitorUpdateStatus::Completed),
			0x06 => harness.nodes[2].set_persistence_style(ChannelMonitorUpdateStatus::Completed),

			0x08 => {
				for id in harness.ab_link.channel_ids() {
					harness.nodes[0].complete_all_monitor_updates(id);
				}
			},
			0x09 => {
				for id in harness.ab_link.channel_ids() {
					harness.nodes[1].complete_all_monitor_updates(id);
				}
			},
			0x0a => {
				for id in harness.bc_link.channel_ids() {
					harness.nodes[1].complete_all_monitor_updates(id);
				}
			},
			0x0b => {
				for id in harness.bc_link.channel_ids() {
					harness.nodes[2].complete_all_monitor_updates(id);
				}
			},

			0x0c => harness.disconnect_ab(),
			0x0d => harness.disconnect_bc(),
			0x0e => harness.reconnect_ab(),
			0x0f => harness.reconnect_bc(),

			0x10 => harness.process_msg_noret(0, true, ProcessMessages::AllMessages),
			0x11 => harness.process_msg_noret(0, false, ProcessMessages::AllMessages),
			0x12 => harness.process_msg_noret(0, true, ProcessMessages::OneMessage),
			0x13 => harness.process_msg_noret(0, false, ProcessMessages::OneMessage),
			0x14 => harness.process_msg_noret(0, true, ProcessMessages::OnePendingMessage),
			0x15 => harness.process_msg_noret(0, false, ProcessMessages::OnePendingMessage),

			0x16 => harness.process_ev_noret(0, true),
			0x17 => harness.process_ev_noret(0, false),

			0x18 => harness.process_msg_noret(1, true, ProcessMessages::AllMessages),
			0x19 => harness.process_msg_noret(1, false, ProcessMessages::AllMessages),
			0x1a => harness.process_msg_noret(1, true, ProcessMessages::OneMessage),
			0x1b => harness.process_msg_noret(1, false, ProcessMessages::OneMessage),
			0x1c => harness.process_msg_noret(1, true, ProcessMessages::OnePendingMessage),
			0x1d => harness.process_msg_noret(1, false, ProcessMessages::OnePendingMessage),

			0x1e => harness.process_ev_noret(1, true),
			0x1f => harness.process_ev_noret(1, false),

			0x20 => harness.process_msg_noret(2, true, ProcessMessages::AllMessages),
			0x21 => harness.process_msg_noret(2, false, ProcessMessages::AllMessages),
			0x22 => harness.process_msg_noret(2, true, ProcessMessages::OneMessage),
			0x23 => harness.process_msg_noret(2, false, ProcessMessages::OneMessage),
			0x24 => harness.process_msg_noret(2, true, ProcessMessages::OnePendingMessage),
			0x25 => harness.process_msg_noret(2, false, ProcessMessages::OnePendingMessage),

			0x26 => harness.process_ev_noret(2, true),
			0x27 => harness.process_ev_noret(2, false),

			// 1/10th the channel size:
			0x30 => harness.send(0, 1, 10_000_000),
			0x31 => harness.send(1, 0, 10_000_000),
			0x32 => harness.send(1, 2, 10_000_000),
			0x33 => harness.send(2, 1, 10_000_000),
			0x34 => harness.send_hop(0, 1, 2, 10_000_000),
			0x35 => harness.send_hop(2, 1, 0, 10_000_000),

			0x38 => harness.send(0, 1, 1_000_000),
			0x39 => harness.send(1, 0, 1_000_000),
			0x3a => harness.send(1, 2, 1_000_000),
			0x3b => harness.send(2, 1, 1_000_000),
			0x3c => harness.send_hop(0, 1, 2, 1_000_000),
			0x3d => harness.send_hop(2, 1, 0, 1_000_000),

			0x40 => harness.send(0, 1, 100_000),
			0x41 => harness.send(1, 0, 100_000),
			0x42 => harness.send(1, 2, 100_000),
			0x43 => harness.send(2, 1, 100_000),
			0x44 => harness.send_hop(0, 1, 2, 100_000),
			0x45 => harness.send_hop(2, 1, 0, 100_000),

			0x48 => harness.send(0, 1, 10_000),
			0x49 => harness.send(1, 0, 10_000),
			0x4a => harness.send(1, 2, 10_000),
			0x4b => harness.send(2, 1, 10_000),
			0x4c => harness.send_hop(0, 1, 2, 10_000),
			0x4d => harness.send_hop(2, 1, 0, 10_000),

			0x50 => harness.send(0, 1, 1_000),
			0x51 => harness.send(1, 0, 1_000),
			0x52 => harness.send(1, 2, 1_000),
			0x53 => harness.send(2, 1, 1_000),
			0x54 => harness.send_hop(0, 1, 2, 1_000),
			0x55 => harness.send_hop(2, 1, 0, 1_000),

			0x58 => harness.send(0, 1, 100),
			0x59 => harness.send(1, 0, 100),
			0x5a => harness.send(1, 2, 100),
			0x5b => harness.send(2, 1, 100),
			0x5c => harness.send_hop(0, 1, 2, 100),
			0x5d => harness.send_hop(2, 1, 0, 100),

			0x60 => harness.send(0, 1, 10),
			0x61 => harness.send(1, 0, 10),
			0x62 => harness.send(1, 2, 10),
			0x63 => harness.send(2, 1, 10),
			0x64 => harness.send_hop(0, 1, 2, 10),
			0x65 => harness.send_hop(2, 1, 0, 10),

			0x68 => harness.send(0, 1, 1),
			0x69 => harness.send(1, 0, 1),
			0x6a => harness.send(1, 2, 1),
			0x6b => harness.send(2, 1, 1),
			0x6c => harness.send_hop(0, 1, 2, 1),
			0x6d => harness.send_hop(2, 1, 0, 1),

			// MPP payments
			// 0x70: direct MPP from 0 to 1 (multi A-B channels)
			0x70 => harness.send_mpp_direct(0, 1, MppDirectChannels::All, 1_000_000),
			// 0x71: MPP 0->1->2, multi channels on first hop (A-B)
			0x71 => harness.send_mpp_hop(0, 1, 2, MppHopChannels::FirstHop, 1_000_000),
			// 0x72: MPP 0->1->2, multi channels on both hops (A-B and B-C)
			0x72 => harness.send_mpp_hop(0, 1, 2, MppHopChannels::BothHops, 1_000_000),
			// 0x73: MPP 0->1->2, multi channels on second hop (B-C)
			0x73 => harness.send_mpp_hop(0, 1, 2, MppHopChannels::SecondHop, 1_000_000),
			// 0x74: direct MPP from 0 to 1, multi parts over single channel
			0x74 => harness.send_mpp_direct(0, 1, MppDirectChannels::RepeatedFirst, 1_000_000),

			0x80 => harness.nodes[0].bump_fee_estimate(harness.chan_type),
			0x81 => harness.nodes[0].reset_fee_estimate(),
			0x84 => harness.nodes[1].bump_fee_estimate(harness.chan_type),
			0x85 => harness.nodes[1].reset_fee_estimate(),
			0x88 => harness.nodes[2].bump_fee_estimate(harness.chan_type),
			0x89 => harness.nodes[2].reset_fee_estimate(),

			0xa0 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[0].splice_in(&cp_node_id, &harness.chan_a_id());
			},
			0xa1 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[0].get_our_node_id();
				harness.nodes[1].splice_in(&cp_node_id, &harness.chan_a_id());
			},
			0xa2 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[2].get_our_node_id();
				harness.nodes[1].splice_in(&cp_node_id, &harness.chan_b_id());
			},
			0xa3 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[2].splice_in(&cp_node_id, &harness.chan_b_id());
			},

			0xa4 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[0].splice_out(&cp_node_id, &harness.chan_a_id());
			},
			0xa5 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[0].get_our_node_id();
				harness.nodes[1].splice_out(&cp_node_id, &harness.chan_a_id());
			},
			0xa6 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[2].get_our_node_id();
				harness.nodes[1].splice_out(&cp_node_id, &harness.chan_b_id());
			},
			0xa7 => {
				if !cfg!(splicing) {
					break 'fuzz_loop;
				}
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[2].splice_out(&cp_node_id, &harness.chan_b_id());
			},

			// Sync node by 1 block to cover confirmation of a transaction.
			0xa8 => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[0].sync_with_chain_state(&harness.chain_state, Some(1));
			},
			0xa9 => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[1].sync_with_chain_state(&harness.chain_state, Some(1));
			},
			0xaa => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[2].sync_with_chain_state(&harness.chain_state, Some(1));
			},
			// Sync node to chain tip to cover confirmation of a transaction post-reorg-risk.
			0xab => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[0].sync_with_chain_state(&harness.chain_state, None);
			},
			0xac => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[1].sync_with_chain_state(&harness.chain_state, None);
			},
			0xad => {
				harness.chain_state.confirm_pending_txs();
				harness.nodes[2].sync_with_chain_state(&harness.chain_state, None);
			},

			0xb0 | 0xb1 | 0xb2 => {
				// Restart node A, picking among persisted and in-flight `ChannelMonitor`
				// candidates based on the value of `v` we're matching.
				harness.restart_node(0, v, &router);
			},
			0xb3..=0xbb => {
				// Restart node B, picking among persisted and in-flight `ChannelMonitor`
				// candidates based on the value of `v` we're matching.
				harness.restart_node(1, v, &router);
			},
			0xbc | 0xbd | 0xbe => {
				// Restart node C, picking among persisted and in-flight `ChannelMonitor`
				// candidates based on the value of `v` we're matching.
				harness.restart_node(2, v, &router);
			},

			0xc0 => harness.nodes[0].keys_manager.disable_supported_ops_for_all_signers(),
			0xc1 => harness.nodes[1].keys_manager.disable_supported_ops_for_all_signers(),
			0xc2 => harness.nodes[2].keys_manager.disable_supported_ops_for_all_signers(),
			0xc3 => {
				harness.nodes[0]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				harness.nodes[0].signer_unblocked(None);
			},
			0xc4 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				let filter = Some((harness.nodes[0].get_our_node_id(), harness.chan_a_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xc5 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				let filter = Some((harness.nodes[2].get_our_node_id(), harness.chan_b_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xc6 => {
				harness.nodes[2]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				harness.nodes[2].signer_unblocked(None);
			},
			0xc7 => {
				harness.nodes[0]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				harness.nodes[0].signer_unblocked(None);
			},
			0xc8 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				let filter = Some((harness.nodes[0].get_our_node_id(), harness.chan_a_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xc9 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				let filter = Some((harness.nodes[2].get_our_node_id(), harness.chan_b_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xca => {
				harness.nodes[2]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				harness.nodes[2].signer_unblocked(None);
			},
			0xcb => {
				harness.nodes[0]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				harness.nodes[0].signer_unblocked(None);
			},
			0xcc => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				let filter = Some((harness.nodes[0].get_our_node_id(), harness.chan_a_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xcd => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				let filter = Some((harness.nodes[2].get_our_node_id(), harness.chan_b_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xce => {
				harness.nodes[2]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				harness.nodes[2].signer_unblocked(None);
			},

			0xf0 => harness.ab_link.complete_monitor_updates_for_node(
				0,
				&harness.nodes,
				MonitorUpdateSelector::First,
			),
			0xf1 => harness.ab_link.complete_monitor_updates_for_node(
				0,
				&harness.nodes,
				MonitorUpdateSelector::Second,
			),
			0xf2 => harness.ab_link.complete_monitor_updates_for_node(
				0,
				&harness.nodes,
				MonitorUpdateSelector::Last,
			),

			0xf4 => harness.ab_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::First,
			),
			0xf5 => harness.ab_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::Second,
			),
			0xf6 => harness.ab_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::Last,
			),

			0xf8 => harness.bc_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::First,
			),
			0xf9 => harness.bc_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::Second,
			),
			0xfa => harness.bc_link.complete_monitor_updates_for_node(
				1,
				&harness.nodes,
				MonitorUpdateSelector::Last,
			),

			0xfc => harness.bc_link.complete_monitor_updates_for_node(
				2,
				&harness.nodes,
				MonitorUpdateSelector::First,
			),
			0xfd => harness.bc_link.complete_monitor_updates_for_node(
				2,
				&harness.nodes,
				MonitorUpdateSelector::Second,
			),
			0xfe => harness.bc_link.complete_monitor_updates_for_node(
				2,
				&harness.nodes,
				MonitorUpdateSelector::Last,
			),

			0xff => {
				// Test that no channel is in a stuck state where neither party can send funds even
				// after we resolve all pending events.
				harness.settle_all();
			},
			_ => break 'fuzz_loop,
		}

		harness.refresh_serialized_managers();
	}
	harness.finish();
}

pub fn chanmon_consistency_test<Out: Output + MaybeSend + MaybeSync>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn chanmon_consistency_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
