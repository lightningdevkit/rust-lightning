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
//! in us getting out of sync with ourselves, and, assuming at least one of our receive- or
//! send-side handling is correct, other peers. The fuzzer also models a small mempool and
//! exercises controlled force-closes, including user-initiated closes and timeout-driven closes,
//! through on-chain confirmation and cleanup.

use bitcoin::amount::Amount;
use bitcoin::constants::genesis_block;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::transaction::Version;
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::FeeRate;
use bitcoin::OutPoint as BitcoinOutPoint;

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
use lightning::chain::channelmonitor::{
	Balance, ChannelMonitor, ANTI_REORG_DELAY, HTLC_FAIL_BACK_BUFFER,
};
use lightning::chain::{
	chainmonitor, channelmonitor, BlockLocator, ChannelMonitorUpdateStatus, Confirm, Watch,
};
use lightning::events::{self, EventsProvider};
use lightning::ln::channel::{
	FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS,
};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{
	ChainParameters, ChannelManager, ChannelManagerReadArgs, PaymentId, RecentPaymentDetails,
	TrustedChannelFeatures, MIN_CLTV_EXPIRY_DELTA, MIN_FINAL_CLTV_EXPIRY_DELTA,
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

use lightning::events::bump_transaction::sync::BumpTransactionEventHandlerSync;

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
const MAX_SETTLE_ITERATIONS: usize = 256;
// The fuzz wallet needs enough confirmed inputs for splice, anchor, and claim
// transactions so failures come from on-chain close handling rather than from
// the harness running out of wallet inputs.
const NUM_WALLET_UTXOS: u32 = 50;
// A single fuzz byte can mine more than one block so a corpus entry does not
// need long runs of identical "mine one block" commands to reach CSV or CLTV
// boundaries. The early entries remain small so the fuzzer can still explore
// fine-grained height changes.
const MINE_BLOCK_COUNTS: [u32; 8] = [1, 2, 3, 6, 12, 24, 48, 144];
// Progress loops are capped so `0xff` and cleanup paths can drive realistic
// asynchronous work without letting a malformed state spin forever.
const QUIESCENCE_ROUNDS: usize = 32;
// Force-close cleanup may require many height advances because claims can be
// chained through commitment, HTLC, anchor, and delayed-output transactions.
// This is intentionally large, but still finite, so a stuck cleanup becomes an
// assertion instead of an infinite fuzz run.
const FORCE_CLOSE_CLEANUP_ROUNDS: usize = 4096;
// Use LDK's minimum CLTV deltas to keep timeout-driven close scenarios reachable
// in short fuzz inputs while still respecting the library's configured limits.
const FUZZ_FINAL_CLTV_DELTA: u32 = MIN_FINAL_CLTV_EXPIRY_DELTA as u32;
const FUZZ_FORWARD_CLTV_DELTA: u32 = MIN_CLTV_EXPIRY_DELTA as u32;

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
	/// Unconfirmed transactions admitted to the mempool, in valid block order:
	/// every input is either confirmed already or created by an earlier
	/// transaction in this vector.
	pending_txs: Vec<(Txid, Transaction)>,
	/// Unspent outputs created by confirmed transactions. Mempool admission
	/// checks inputs against this set, adjusted for outputs created and spent
	/// by the transactions already in `pending_txs`.
	utxos: HashSet<BitcoinOutPoint>,
}

impl ChainState {
	fn new() -> Self {
		let genesis_hash = genesis_block(Network::Bitcoin).block_hash();
		let genesis_header = create_dummy_header(genesis_hash, 42);
		Self {
			blocks: vec![(genesis_header, Vec::new())],
			confirmed_txids: HashSet::new(),
			pending_txs: Vec::new(),
			utxos: HashSet::new(),
		}
	}

	fn tip_height(&self) -> u32 {
		(self.blocks.len() - 1) as u32
	}

	fn is_unspent(&self, outpoint: &BitcoinOutPoint) -> bool {
		self.utxos.contains(outpoint)
	}

	fn is_confirmed_txid(&self, txid: &Txid) -> bool {
		self.confirmed_txids.contains(txid)
	}

	fn confirmed_output(&self, outpoint: &BitcoinOutPoint) -> Option<&TxOut> {
		if !self.confirmed_txids.contains(&outpoint.txid) {
			return None;
		}
		self.blocks.iter().find_map(|(_, txs)| {
			txs.iter().find_map(|tx| {
				if tx.compute_txid() == outpoint.txid {
					tx.output.get(outpoint.vout as usize)
				} else {
					None
				}
			})
		})
	}

	// Initial channel funding is represented by a no-input transaction. It is
	// not a valid Bitcoin transaction, but it gives LDK a stable funding
	// outpoint without modeling coin selection during channel setup.
	fn is_synthetic_funding_tx(tx: &Transaction) -> bool {
		!tx.is_coinbase() && tx.input.is_empty()
	}

	// Checks whether a transaction spends an input twice or spends an output
	// not present in `utxos`.
	fn has_invalid_inputs(tx: &Transaction, utxos: &HashSet<BitcoinOutPoint>) -> bool {
		let mut spent_inputs = HashSet::new();
		for input in &tx.input {
			if !spent_inputs.insert(input.previous_output) {
				return true;
			}
			if !utxos.contains(&input.previous_output) {
				return true;
			}
		}
		false
	}

	fn apply_tx_to_utxos(&mut self, txid: Txid, tx: &Transaction) {
		for input in &tx.input {
			self.utxos.remove(&input.previous_output);
		}
		for idx in 0..tx.output.len() {
			self.utxos.insert(BitcoinOutPoint { txid, vout: idx as u32 });
		}
	}

	fn mine_block(&mut self, txs: Vec<Transaction>) {
		let prev_hash = self.blocks.last().unwrap().0.block_hash();
		let header = create_dummy_header(prev_hash, 42);
		self.blocks.push((header, txs));
	}

	fn mine_empty_blocks(&mut self, count: u32) {
		for _ in 0..count {
			self.mine_block(Vec::new());
		}
	}

	// Mines a setup transaction directly into a block, bypassing the mempool,
	// and buries it to `depth`. Wallet seeding and synthetic funding
	// transactions are not relayable, so they cannot go through normal
	// admission.
	fn mine_setup_tx_to_depth(&mut self, tx: Transaction, depth: u32) {
		assert!(
			tx.is_coinbase() || Self::is_synthetic_funding_tx(&tx),
			"direct setup mining is only for coinbase and synthetic funding transactions: {:?}",
			tx,
		);
		let txid = tx.compute_txid();
		assert!(
			self.confirmed_txids.insert(txid),
			"direct setup transaction was already confirmed: {:?}",
			tx,
		);
		self.apply_tx_to_utxos(txid, &tx);

		self.mine_block(vec![tx]);
		self.mine_empty_blocks(depth.saturating_sub(1));
	}

	// Attempts to admit a broadcast transaction to the mempool, enforcing
	// locktime, input, and RBF rules. Mining later confirms the whole mempool
	// without further selection.
	fn admit_tx_to_mempool(&mut self, tx: Transaction) {
		let txid = tx.compute_txid();
		let lock_time = tx.lock_time.to_consensus_u32();
		let locktime_enabled =
			tx.input.iter().any(|input| input.sequence.enables_absolute_lock_time());

		// Commitment transactions split the obscured commitment number across
		// nSequence and nLockTime with fixed top bytes 0x80 and 0x20. The
		// non-final sequence makes nLockTime relevant, and the 0x20 top byte
		// puts the value above the 500M timestamp threshold even though it is
		// not a fuzz-driven wall-clock lock.
		let is_ldk_commitment_obscured_locktime =
			tx.input.len() == 1 && tx.input[0].sequence.0 >> 24 == 0x80 && lock_time >> 24 == 0x20;

		let immature_absolute_locktime =
			locktime_enabled && tx.lock_time.is_block_height() && self.tip_height() < lock_time;
		assert!(
			!immature_absolute_locktime,
			"broadcast immature locktime transaction into chanmon harness mempool: {:?}",
			tx,
		);

		let unmodeled_time_locktime = locktime_enabled
			&& tx.lock_time.is_block_time()
			&& !is_ldk_commitment_obscured_locktime;
		assert!(
			!unmodeled_time_locktime,
			"broadcast time-locked transaction into chanmon harness mempool: {:?}",
			tx,
		);

		assert!(
			!tx.is_coinbase() && !Self::is_synthetic_funding_tx(&tx),
			"setup-only transaction entered chanmon harness mempool: {:?}",
			tx,
		);

		if self.confirmed_txids.contains(&txid) {
			return;
		}
		if self.pending_txs.iter().any(|(pending_txid, _)| *pending_txid == txid) {
			return;
		}

		// Fee-rate policy is not modeled, so among conflicting RBF candidates
		// the last one relayed wins.
		let mut conflicting_pending_txids = HashSet::new();
		for (pending_txid, pending_tx) in &self.pending_txs {
			let signals_rbf = pending_tx.input.iter().any(|input| input.sequence.is_rbf());
			let conflicts_with_new_tx = pending_tx.input.iter().any(|pending_input| {
				tx.input.iter().any(|input| input.previous_output == pending_input.previous_output)
			});
			if conflicts_with_new_tx {
				if !signals_rbf {
					return;
				}
				conflicting_pending_txids.insert(*pending_txid);
			}
		}
		if !conflicting_pending_txids.is_empty() {
			let mut removed_outputs = HashSet::new();
			let mut retained_txs = Vec::new();
			for (pending_txid, pending_tx) in self.pending_txs.drain(..) {
				let direct_conflict = conflicting_pending_txids.contains(&pending_txid);
				let spends_removed_tx = pending_tx
					.input
					.iter()
					.any(|input| removed_outputs.contains(&input.previous_output));
				if direct_conflict || spends_removed_tx {
					for idx in 0..pending_tx.output.len() {
						removed_outputs
							.insert(BitcoinOutPoint { txid: pending_txid, vout: idx as u32 });
					}
				} else {
					retained_txs.push((pending_txid, pending_tx));
				}
			}
			self.pending_txs = retained_txs;
		}

		// Build the UTXO set this transaction would see if the current mempool
		// confirmed.
		let mut available_utxos = self.utxos.clone();
		for (pending_txid, pending_tx) in &self.pending_txs {
			for input in &pending_tx.input {
				available_utxos.remove(&input.previous_output);
			}
			for idx in 0..pending_tx.output.len() {
				available_utxos.insert(BitcoinOutPoint { txid: *pending_txid, vout: idx as u32 });
			}
		}
		if Self::has_invalid_inputs(&tx, &available_utxos) {
			return;
		}
		self.pending_txs.push((txid, tx));
	}

	// Feeds broadcast transactions through modeled mempool admission. Returns
	// whether any broadcasts were drained, even if admission later ignores a
	// duplicate or invalid transaction.
	fn relay_transactions(&mut self, txs: Vec<Transaction>) -> bool {
		let found = !txs.is_empty();
		for tx in txs {
			self.admit_tx_to_mempool(tx);
		}
		found
	}

	// Reports whether the modeled mempool is non-empty. Fuzz mining bytes and
	// cleanup loops use this to decide whether another mining pass can make
	// progress.
	fn has_pending_txs(&self) -> bool {
		!self.pending_txs.is_empty()
	}

	// Mines `count` blocks, confirming the current mempool in the first block.
	fn mine_blocks(&mut self, count: u32) -> Vec<Transaction> {
		assert!(count > 0, "mining zero blocks should not be requested");

		let mempool_txs = std::mem::take(&mut self.pending_txs);
		let confirmed_txs = if mempool_txs.is_empty() {
			self.mine_empty_blocks(1);
			Vec::new()
		} else {
			let mut confirmed = Vec::new();
			for (txid, tx) in mempool_txs {
				assert!(
					!Self::has_invalid_inputs(&tx, &self.utxos),
					"mempool transaction was no longer valid at mining time: {:?}",
					tx,
				);
				assert!(
					self.confirmed_txids.insert(txid),
					"mempool transaction was already confirmed at mining time: {:?}",
					tx,
				);
				self.apply_tx_to_utxos(txid, &tx);
				confirmed.push(tx);
			}
			let confirmed_txs = confirmed.clone();
			self.mine_block(confirmed);
			confirmed_txs
		};
		self.mine_empty_blocks(count - 1);
		confirmed_txs
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
type TestBumpTransactionEventHandler = BumpTransactionEventHandlerSync<
	Arc<TestBroadcaster>,
	Arc<WalletSync<Arc<TestWalletSource>, Arc<dyn Logger + MaybeSend + MaybeSync>>>,
	Arc<KeyProvider>,
	Arc<dyn Logger + MaybeSend + MaybeSync>,
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

// Signer ops that fuzz bytes may block. The holder-side ops matter after a
// force-close, when monitors build holder commitment or HTLC claim
// transactions; `settle_all` re-enables everything so final failures are not
// caused by intentionally blocked signing.
const SUPPORTED_SIGNER_OPS: [SignerOp; 6] = [
	SignerOp::SignCounterpartyCommitment,
	SignerOp::GetPerCommitmentPoint,
	SignerOp::ReleaseCommitmentSecret,
	SignerOp::SignSpliceSharedInput,
	SignerOp::SignHolderCommitment,
	SignerOp::SignHolderHtlcTransaction,
];
// LDK reports expected force-close paths through message text in a few places.
// The harness keeps these strings centralized so reviewers can audit exactly
// which peer errors are treated as control-flow artifacts of the test.
const HTLC_TIMEOUT_ERROR_PREFIX: &str = "Channel closed because HTLC(s) on the channel timed out";
const ONCHAIN_TX_CONFIRMED_ERROR: &str =
	"Channel closed because commitment or closing transaction was confirmed on chain.";
const CLOSED_CHANNEL_WRONG_NODE_ERROR_PREFIX: &str =
	"Got a message for a channel from the wrong node! No such channel_id";
const INVALID_REESTABLISH_FORCE_CLOSE_ERROR: &str =
	"Peer sent an invalid channel_reestablish to force close in a non-standard way";
const NEEDED_CHANNEL_REESTABLISH_ERROR: &str = "when we needed a channel_reestablish";
// Bounds for accepting a non-explicit close as an HTLC-timeout close, mirroring
// the monitor's force-close conditions: an outbound HTLC closes the channel once
// `LATENCY_GRACE_PERIOD_BLOCKS` past expiry, an inbound HTLC with a known
// preimage once expiry is within `CLTV_CLAIM_BUFFER` blocks. Both LDK constants
// are private, so derive the claim buffer from the public fail-back buffer to
// catch drift.
const HTLC_TIMEOUT_GRACE_BLOCKS: u32 = 3;
const HTLC_CLAIM_BUFFER_BLOCKS: u32 = HTLC_FAIL_BACK_BUFFER - HTLC_TIMEOUT_GRACE_BLOCKS;
// These distinct short strings let the harness recognize user force-close
// errors without accepting arbitrary SendErrorMessage actions.
const FORCE_CLOSE_ERROR_MESSAGES: [&str; 4] = ["]]]]]]]]]", "]]]]]]]]", "]]]]]]]", "]]]]]"];

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

// Recognizes splice-quiescence warning disconnects, which are recoverable and
// must be distinguished from real close errors.
fn is_quiescent_disconnect_warning(msg: &msgs::WarningMessage) -> bool {
	msg.data.contains("already sent splice_locked, cannot RBF")
		|| msg.data.contains("contribution no longer valid at quiescence")
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
	wallet: Arc<TestWalletSource>,
	wallet_sync: WalletSync<Arc<TestWalletSource>, Arc<dyn Logger + MaybeSend + MaybeSync>>,
	bump_tx_handler: TestBumpTransactionEventHandler,
	persistence_style: ChannelMonitorUpdateStatus,
	deferred: bool,
	serialized_manager: Vec<u8>,
	serialized_manager_generation: u64,
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
		persister: &Arc<HarnessPersister>, deferred: bool,
	) -> Arc<TestChainMonitor> {
		// The monitor shares the node's broadcaster so post-close claim and
		// bump transactions reach the same queue that relay commands drain.
		Arc::new(chainmonitor::ChainMonitor::new(
			None,
			Arc::clone(broadcaster),
			logger,
			Arc::clone(fee_estimator),
			Arc::clone(persister),
			Arc::clone(keys_manager),
			keys_manager.get_peer_storage_key(),
			deferred,
		))
	}

	fn new<Out: Output + MaybeSend + MaybeSync>(
		node_id: u8, wallet: Arc<TestWalletSource>, fee_estimator: Arc<FuzzEstimator>,
		broadcaster: Arc<TestBroadcaster>, persistence_style: ChannelMonitorUpdateStatus,
		deferred: bool, out: &Out, router: &'a FuzzRouter, chan_type: ChanType,
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
			deferred,
		);
		let wallet_sync = WalletSync::new(Arc::clone(&wallet), Arc::clone(&logger));
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
		let bump_wallet_sync = Arc::new(WalletSync::new(Arc::clone(&wallet), Arc::clone(&logger)));
		// Wallet-backed handler that turns BumpTransaction events into complete,
		// broadcast anchor and HTLC claim transactions.
		let bump_tx_handler = BumpTransactionEventHandlerSync::new(
			Arc::clone(&broadcaster),
			bump_wallet_sync,
			Arc::clone(&keys_manager),
			Arc::clone(&logger),
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
			wallet_sync,
			bump_tx_handler,
			persistence_style,
			deferred,
			serialized_manager: Vec::new(),
			serialized_manager_generation: 0,
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

	fn manager_height(&self) -> u32 {
		self.node.current_best_block().height
	}

	// Connects a block range to ChainMonitor and ChannelManager. The start
	// heights are independent because reload may pair monitors and a manager
	// persisted at different chain tips.
	fn connect_chain_range(
		&mut self, chain_state: &ChainState, monitor_start_height: u32, manager_start_height: u32,
		target_height: u32,
	) {
		assert!(
			target_height >= monitor_start_height,
			"connect_chain_range cannot move monitor height backward ({} -> {})",
			monitor_start_height,
			target_height
		);
		assert!(
			target_height >= manager_start_height,
			"connect_chain_range cannot move manager height backward ({} -> {})",
			manager_start_height,
			target_height
		);
		let start_height = cmp::min(monitor_start_height, manager_start_height);
		let mut height = start_height;
		while height < target_height {
			let mut next_height = height + 1;
			while next_height <= target_height && chain_state.block_at(next_height).1.is_empty() {
				next_height += 1;
			}
			if next_height > target_height {
				// The rest of the range is empty. One best-block update to the
				// final height is enough because LDK's Confirm API explicitly
				// allows best_block_updated to skip intermediary blocks.
				height = target_height;
				let (header, _) = chain_state.block_at(height);
				if height > monitor_start_height {
					self.monitor.best_block_updated(header, height);
				}
				if height > manager_start_height {
					self.node.best_block_updated(header, height);
				}
				break;
			}
			height = next_height;
			let (header, txn) = chain_state.block_at(height);
			let txdata: Vec<_> = txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			if height > monitor_start_height {
				self.monitor.transactions_confirmed(header, &txdata, height);
			}
			if height > manager_start_height {
				self.node.transactions_confirmed(header, &txdata, height);
			}
			if height > monitor_start_height {
				self.monitor.best_block_updated(header, height);
			}
			if height > manager_start_height {
				self.node.best_block_updated(header, height);
			}
		}
	}

	fn sync_with_chain_state(&mut self, chain_state: &ChainState, num_blocks: Option<u32>) {
		let target_height = if let Some(num_blocks) = num_blocks {
			std::cmp::min(self.manager_height() + num_blocks, chain_state.tip_height())
		} else {
			chain_state.tip_height()
		};

		let start_height = self.manager_height();
		self.connect_chain_range(chain_state, start_height, start_height, target_height);
	}

	fn checkpoint_manager_persistence(&mut self) -> bool {
		if self.node.get_and_clear_needs_persistence() {
			let pending_monitor_writes = self.monitor.pending_operation_count();
			self.serialized_manager = self.node.encode();
			self.serialized_manager_generation += 1;
			if self.deferred {
				self.monitor.flush(pending_monitor_writes, &self.logger);
			} else {
				assert_eq!(pending_monitor_writes, 0);
			}
			true
		} else {
			assert_eq!(self.monitor.pending_operation_count(), 0);
			false
		}
	}

	fn force_checkpoint_manager_persistence(&mut self) {
		let pending_monitor_writes = self.monitor.pending_operation_count();
		self.serialized_manager = self.node.encode();
		self.serialized_manager_generation += 1;
		self.node.get_and_clear_needs_persistence();
		if self.deferred {
			self.monitor.flush(pending_monitor_writes, &self.logger);
		} else {
			assert_eq!(pending_monitor_writes, 0);
		}
	}

	fn next_manager_persistence_generation(&self) -> u64 {
		self.serialized_manager_generation + 1
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

	// Re-enables holder claim signing and asks the chain monitor to retry
	// pending claim transactions. Different on-chain claim paths use
	// SignHolderCommitment or SignHolderHtlcTransaction for force-closed channels.
	fn enable_holder_signer_ops(&self) {
		self.keys_manager.enable_op_for_all_signers(SignerOp::SignHolderCommitment);
		self.keys_manager.enable_op_for_all_signers(SignerOp::SignHolderHtlcTransaction);
		self.monitor.signer_unblocked(None);
	}

	fn current_feerate_sat_per_kw(&self) -> FeeRate {
		self.fee_estimator.feerate_sat_per_kw()
	}

	fn record_last_htlc_clear_fee(&mut self) {
		self.last_htlc_clear_fee = self.fee_estimator.ret_val.load(atomic::Ordering::Acquire);
	}

	fn splice_in(&self, counterparty_node_id: &PublicKey, channel_id: &ChannelId) {
		match self.node.splice_channel(channel_id, counterparty_node_id) {
			Ok(funding_template) => {
				let feerate =
					funding_template.min_rbf_feerate().unwrap_or(self.current_feerate_sat_per_kw());
				if let Ok(contribution) = funding_template.splice_in_sync(
					Amount::from_sat(10_000),
					feerate,
					FeeRate::MAX,
					&self.wallet_sync,
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

	// Drains raw ChannelMonitor events. Monitor-generated BumpTransaction events
	// do not flow through the manager event queue but still produce transactions
	// the harness must mine.
	fn process_monitor_pending_events(&self) {
		self.monitor.process_pending_events(&|event: events::Event| {
			if let events::Event::BumpTransaction(ref bump) = event {
				self.bump_tx_handler.handle_event(bump);
			}
			Ok(())
		});
	}

	fn reload<Out: Output + MaybeSend + MaybeSync>(
		&mut self, use_old_mons: u8, out: &Out, router: &'a FuzzRouter, chan_type: ChanType,
	) -> u64 {
		let loaded_manager_generation = self.serialized_manager_generation;
		let logger = Self::build_logger(self.node_id, out);
		let persister = Self::build_persister(self.persistence_style);
		let chain_monitor = Self::build_chain_monitor(
			&self.broadcaster,
			&self.fee_estimator,
			&self.keys_manager,
			Arc::clone(&logger),
			&persister,
			self.deferred,
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
		let expected_status = if self.deferred {
			ChannelMonitorUpdateStatus::InProgress
		} else {
			self.persistence_style
		};
		for (channel_id, mon) in monitors.drain() {
			assert_eq!(chain_monitor.watch_channel(channel_id, mon), Ok(expected_status));
		}
		self.node = manager.1;
		self.monitor = chain_monitor;
		self.persister = persister;
		self.logger = logger;
		// In deferred mode, the startup watch_channel registrations above queue monitor operations
		// even if the reloaded ChannelManager does not need persistence. Always checkpoint here so
		// those registrations can be flushed against the manager snapshot they belong to.
		self.force_checkpoint_manager_persistence();
		loaded_manager_generation
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
		close_tracker: &ChannelCloseTracker,
	) {
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
					// Validate before routing so arbitrary HandleError output is
					// not accepted as expected force-close behavior.
					close_tracker.assert_expected_control_error_action(action);
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

	// Drains messages generated by a peer disconnect, validating HandleError
	// events before the link queues are cleared.
	fn drain_on_disconnect(
		&mut self, edge_node: usize, nodes: &[HarnessNode<'_>; 3],
		close_tracker: &ChannelCloseTracker,
	) {
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
							close_tracker.assert_expected_control_error_action(action);
						},
						_ => panic!("Unhandled message event"),
					}
				}
				self.route_from_middle(
					nodes[1].get_and_clear_pending_msg_events(),
					Some(0),
					nodes,
					close_tracker,
				);
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
							close_tracker.assert_expected_control_error_action(action);
						},
						_ => panic!("Unhandled message event"),
					}
				}
				self.route_from_middle(
					nodes[1].get_and_clear_pending_msg_events(),
					Some(2),
					nodes,
					close_tracker,
				);
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

	// Asserts every untracked channel on this link is still listed by both
	// peers, catching a force close that hit the wrong sibling channel.
	fn assert_no_unexpected_channel_closes(
		&self, nodes: &[HarnessNode<'_>; 3], close_tracker: &ChannelCloseTracker,
	) {
		let node_a_channels = nodes[self.node_a].list_channels();
		let node_b_channels = nodes[self.node_b].list_channels();
		for channel_id in &self.channel_ids {
			if close_tracker.is_closed_or_closing(channel_id) {
				continue;
			}
			assert!(
				node_a_channels.iter().any(|chan| chan.channel_id == *channel_id),
				"Node {} no longer lists channel {:?} without an intentional force-close",
				self.node_a,
				channel_id,
			);
			assert!(
				node_b_channels.iter().any(|chan| chan.channel_id == *channel_id),
				"Node {} no longer lists channel {:?} without an intentional force-close",
				self.node_b,
				channel_id,
			);
		}
	}

	// Records channels from this link that disappeared from list_channels
	// without a tracked close.
	fn record_disappeared_channels(
		&self, nodes: &[HarnessNode<'_>; 3], close_tracker: &mut ChannelCloseTracker,
	) {
		let node_a_channels = nodes[self.node_a].list_channels();
		let node_b_channels = nodes[self.node_b].list_channels();
		for channel_id in &self.channel_ids {
			if close_tracker.is_closed_or_closing(channel_id) {
				continue;
			}
			let node_a_has = node_a_channels.iter().any(|chan| chan.channel_id == *channel_id);
			let node_b_has = node_b_channels.iter().any(|chan| chan.channel_id == *channel_id);
			if !node_a_has || !node_b_has {
				close_tracker.record_unexpected_channel_close(*channel_id);
			}
		}
	}

	fn disconnect(
		&mut self, nodes: &[HarnessNode<'_>; 3], queues: &mut EventQueues,
		close_tracker: &ChannelCloseTracker,
	) {
		if self.disconnected {
			return;
		}
		let node_a_id = nodes[self.node_a].get_our_node_id();
		let node_b_id = nodes[self.node_b].get_our_node_id();
		nodes[self.node_a].peer_disconnected(node_b_id);
		nodes[self.node_b].peer_disconnected(node_a_id);
		self.disconnected = true;
		// Only links involving B are supported. The edge node is the peer whose
		// local messages can be drained directly, while B's newly generated
		// messages may need routing to the other still-connected edge.
		let edge_node = if self.node_a == 1 {
			self.node_b
		} else if self.node_b == 1 {
			self.node_a
		} else {
			panic!("unsupported link topology")
		};
		queues.drain_on_disconnect(edge_node, nodes, close_tracker);
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
		close_tracker: &ChannelCloseTracker,
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
			// If the surviving peer is B, it may still have messages for the
			// other edge node. Route those while asserting nothing is queued for
			// the restarted node that just disconnected.
			queues.route_from_middle(
				nodes[1].get_and_clear_pending_msg_events(),
				Some(restarted_node),
				nodes,
				close_tracker,
			);
		} else {
			nodes[remaining_node].get_and_clear_pending_msg_events();
		}
		queues.clear_link(self);
	}
}

// A tracked path stores only the data the cleanup invariants need later:
// `(channel_id, amount_msat, short_channel_id)`. The channel id lets a close
// or dust threshold mark a path as no longer resolvable through the live
// channel graph. The SCID mirrors the route information in PaymentPathFailed
// events so the harness can match LDK's failure event back to the tracked path.
type PaymentPath = Vec<(ChannelId, u64, u64)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SenderOutcome {
	Sent,
	Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaymentStatus {
	Pending,
	Resolved,
	// The sender ChannelManager was reloaded from a generation older than the
	// send. After that reload, the payment may legitimately never produce a
	// sender-side resolution event.
	RolledBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelCloseState {
	// The harness has a valid reason for this channel to be closing or closed:
	// an explicit force-close command, or an HTLC timeout detected during
	// height sync. Expected channels are treated as unavailable for new sends.
	Expected,
	// The channel disappeared before the harness knew a valid close reason.
	// This lets topology-only observations be recorded and checked by the final
	// close invariant.
	Unexpected,
}

struct ChannelCloseTracker {
	// Absent channels are still considered live. Present channels are closing
	// or already closed, with the value recording whether the close was
	// expected. Keeping one state per channel avoids having to compare separate
	// "observed" and "allowed" sets.
	closed_channels: HashMap<ChannelId, ChannelCloseState>,
}

impl ChannelCloseTracker {
	fn new() -> Self {
		Self { closed_channels: new_hash_map() }
	}

	fn is_closed_or_closing(&self, channel_id: &ChannelId) -> bool {
		self.closed_channels.contains_key(channel_id)
	}

	fn is_expected(&self, channel_id: &ChannelId) -> bool {
		matches!(self.closed_channels.get(channel_id), Some(ChannelCloseState::Expected))
	}

	fn has_closed_channels(&self) -> bool {
		!self.closed_channels.is_empty()
	}

	fn expect_channel_close(&mut self, channel_id: ChannelId) {
		// Upgrades a topology-observed Unexpected entry once a valid close
		// reason is known.
		self.closed_channels.insert(channel_id, ChannelCloseState::Expected);
	}

	// Records a close observed only through topology. It stays Unexpected, and
	// fails the final close invariant, unless a ChannelClosed event or timeout
	// pre-check later upgrades it.
	fn record_unexpected_channel_close(&mut self, channel_id: ChannelId) {
		self.closed_channels.entry(channel_id).or_insert(ChannelCloseState::Unexpected);
	}

	fn record_channel_closed_event(
		&mut self, channel_id: ChannelId, reason: &events::ClosureReason,
	) {
		// Most closes must have been expected before LDK emits ChannelClosed.
		// HTLC timeout closes are the exception: the timeout condition can be
		// observed while connecting the block, so the close event itself carries
		// the evidence.
		let expected_before_close = self.is_expected(&channel_id);
		let allowed_by_htlc_timeout = match reason {
			events::ClosureReason::HTLCsTimedOut { .. } => true,
			events::ClosureReason::CounterpartyForceClosed { peer_msg } => {
				peer_msg.0.starts_with(HTLC_TIMEOUT_ERROR_PREFIX)
			},
			_ => false,
		};
		if allowed_by_htlc_timeout {
			self.expect_channel_close(channel_id);
		}
		assert!(
			expected_before_close || allowed_by_htlc_timeout,
			"Channel {:?} closed without an explicit force-close or HTLC timeout: {:?}",
			channel_id,
			reason,
		);
	}

	// Asserts an LDK HandleError action is one of the error paths the harness
	// can produce intentionally.
	fn assert_expected_control_error_action(&self, action: &msgs::ErrorAction) {
		let expected = match action {
			msgs::ErrorAction::DisconnectPeerWithWarning { msg } => {
				// Warning-only disconnects do not close channels. They are
				// accepted when the fuzzer delays normal protocol progress far
				// enough for a peer timeout, or when splice quiescence needs to
				// be exited.
				msg.data.contains("Disconnecting due to timeout awaiting response")
					|| msg.data.contains("already sent splice_locked, cannot RBF")
			},
			msgs::ErrorAction::SendErrorMessage { msg } => {
				// Error messages can close channels, so they are accepted only
				// for channels that were pre-authorized, or for the narrow
				// timeout and wrong-node messages LDK can emit while peers race
				// with on-chain confirmation.
				msg.data.starts_with(HTLC_TIMEOUT_ERROR_PREFIX)
					|| msg.data.starts_with(CLOSED_CHANNEL_WRONG_NODE_ERROR_PREFIX)
					|| (self.is_expected(&msg.channel_id)
						&& (FORCE_CLOSE_ERROR_MESSAGES.contains(&msg.data.as_str())
							|| msg.data == ONCHAIN_TX_CONFIRMED_ERROR
							|| msg.data == INVALID_REESTABLISH_FORCE_CLOSE_ERROR
							|| msg.data.contains(NEEDED_CHANNEL_REESTABLISH_ERROR)))
			},
			_ => false,
		};
		assert!(expected, "Expected harness control error, got: {:?}", action);
	}

	// Verifies every tracked close was authorized by an explicit force-close
	// command or an HTLC-timeout condition.
	fn assert_no_unexpected_channel_closes(&self) {
		for (channel_id, state) in &self.closed_channels {
			assert!(
				*state == ChannelCloseState::Expected,
				"Channel {:?} closed without an explicit force-close or HTLC timeout",
				channel_id,
			);
		}
	}
}

#[derive(Debug)]
struct PendingPayment {
	source_idx: usize,
	payment_id: PaymentId,
	payment_hash: PaymentHash,
	// The manager generation expected to persist this payment. If a reload uses
	// an older manager snapshot, the payment is marked RolledBack so the cleanup
	// invariant does not wait for an event from a payment the manager forgot.
	first_persisted_manager_generation: u64,
	paths: Vec<PaymentPath>,
	// A blocked path is one that cannot reasonably finish through normal
	// payment events anymore because a channel in that path closed or because
	// the on-chain output would be below dust.
	blocked_paths: HashSet<usize>,
	// A failed path is one LDK explicitly reported through PaymentPathFailed.
	failed_paths: HashSet<usize>,
	status: PaymentStatus,
	// Sender and receiver events are intentionally tracked independently. A
	// claimed on-chain HTLC may produce receiver-side completion before the
	// sender-side PaymentSent or PaymentFailed has propagated back.
	sender_outcome: Option<SenderOutcome>,
	receiver_claimed: bool,
	// Set after the harness calls claim_funds. It stays set until the receiver
	// sees PaymentClaimed, or until LDK rejects the local claim before it can be
	// made safe on chain.
	claim_funds_called: bool,
}

impl PendingPayment {
	// Payments are registered with at least one path, asserted in
	// register_payment, so these do not need an emptiness check.
	fn all_paths_blocked(&self) -> bool {
		(0..self.paths.len()).all(|path_idx| self.blocked_paths.contains(&path_idx))
	}

	fn all_paths_finished(&self) -> bool {
		(0..self.paths.len()).all(|path_idx| {
			self.blocked_paths.contains(&path_idx) || self.failed_paths.contains(&path_idx)
		})
	}
}

struct PaymentTracker {
	payment_ctr: u64,
	records_by_id: HashMap<PaymentId, PendingPayment>,
	ids_by_hash: HashMap<PaymentHash, PaymentId>,
	// Preimages are deterministic so fabricated fuzz inputs can replay the same
	// high-level scenario without relying on randomness.
	payment_preimages: HashMap<PaymentHash, PaymentPreimage>,
}

impl PaymentTracker {
	fn new() -> Self {
		Self {
			payment_ctr: 0,
			records_by_id: new_hash_map(),
			ids_by_hash: new_hash_map(),
			payment_preimages: new_hash_map(),
		}
	}

	// Starts tracking a successfully accepted outbound payment under both its
	// id and hash.
	fn register_payment(
		&mut self, source_idx: usize, payment_id: PaymentId, payment_hash: PaymentHash,
		payment_paths: Vec<PaymentPath>, first_persisted_manager_generation: u64,
	) {
		assert!(!payment_paths.is_empty(), "tracked payment must have at least one path");
		assert!(
			self.ids_by_hash.insert(payment_hash, payment_id).is_none(),
			"duplicate payment_hash {:?}",
			payment_hash
		);
		let record = PendingPayment {
			source_idx,
			payment_id,
			payment_hash,
			first_persisted_manager_generation,
			paths: payment_paths,
			blocked_paths: HashSet::new(),
			failed_paths: HashSet::new(),
			status: PaymentStatus::Pending,
			sender_outcome: None,
			receiver_claimed: false,
			claim_funds_called: false,
		};
		assert!(
			self.records_by_id.insert(payment_id, record).is_none(),
			"duplicate payment_id {:?}",
			payment_id
		);
	}

	fn record_for_hash(&self, hash: &PaymentHash) -> Option<&PendingPayment> {
		let payment_id = self.ids_by_hash.get(hash)?;
		self.records_by_id.get(payment_id)
	}

	fn record_for_hash_mut(&mut self, hash: &PaymentHash) -> Option<&mut PendingPayment> {
		let payment_id = self.ids_by_hash.get(hash).copied()?;
		self.records_by_id.get_mut(&payment_id)
	}

	// Marks payments forgotten by a stale manager reload as rolled back.
	fn sync_pending_with_manager_generation(
		&mut self, node_idx: usize, loaded_manager_generation: u64,
	) -> Vec<PaymentHash> {
		// Reloading from a stale ChannelManager snapshot can roll back a payment
		// that was sent after the persisted generation. Such a payment may still
		// have monitor or peer artifacts, but the reloaded manager cannot be
		// expected to emit its original sender-side completion event.
		let mut rolled_back_payment_hashes = Vec::new();
		for record in self.records_by_id.values_mut() {
			if record.source_idx == node_idx
				&& record.status == PaymentStatus::Pending
				&& record.first_persisted_manager_generation > loaded_manager_generation
			{
				record.status = PaymentStatus::RolledBack;
				rolled_back_payment_hashes.push(record.payment_hash);
			}
		}
		rolled_back_payment_hashes
	}

	// Reports whether any claim_funds call still needs receiver or sender-side
	// accounting.
	fn has_unfinished_claims(&self) -> bool {
		self.records_by_id.values().any(|record| {
			record.claim_funds_called
				&& (!record.receiver_claimed
					|| (record.sender_outcome.is_none() && !record.all_paths_blocked()))
		})
	}

	// Reports whether payment state can still make cleanup progress.
	fn has_live_payment_work(&self) -> bool {
		self.records_by_id
			.values()
			.any(|record| record.status == PaymentStatus::Pending && !record.all_paths_finished())
			|| self.has_unfinished_claims()
	}

	fn claim_funds_called(&self, hash: &PaymentHash) -> bool {
		self.record_for_hash(hash).map(|record| record.claim_funds_called).unwrap_or(false)
	}

	// Clears the claim_funds obligation when LDK rejects the local claim before
	// PaymentClaimed, or when a stale manager reload means the reloaded node can
	// no longer emit that event.
	fn clear_claim(&mut self, hash: &PaymentHash) {
		if let Some(record) = self.record_for_hash_mut(hash) {
			record.claim_funds_called = false;
		}
	}

	// Blocks tracked paths for one payment that used a closed channel, for
	// HTLC-timeout close events that identify the affected hash.
	fn block_paths_containing_channel(&mut self, hash: &PaymentHash, channel_id: ChannelId) {
		if let Some(record) = self.record_for_hash_mut(hash) {
			for path_idx in 0..record.paths.len() {
				let path_contains_channel =
					record.paths[path_idx].iter().any(|(chan_id, _, _)| *chan_id == channel_id);
				if path_contains_channel {
					record.blocked_paths.insert(path_idx);
				}
			}
		}
	}

	// Blocks dust-sized path parts through a closed channel. Dust HTLCs have no
	// commitment output, so once the channel closes they can never resolve
	// through an on-chain claim.
	fn block_dust_paths_containing_channel(&mut self, channel_id: ChannelId, dust_limit_msat: u64) {
		for record in self.records_by_id.values_mut() {
			for path_idx in 0..record.paths.len() {
				if record.blocked_paths.contains(&path_idx) {
					continue;
				}
				let path_contains_dust_part =
					record.paths[path_idx].iter().any(|(chan_id, part_amt, _)| {
						*chan_id == channel_id && *part_amt < dust_limit_msat
					});
				if path_contains_dust_part {
					record.blocked_paths.insert(path_idx);
				}
			}
		}
	}

	// Blocks pending paths through closing channels: once cleanup ends they are
	// unresolvable. The close invariant separately checks that each tracked
	// close was expected.
	fn block_unresolvable_closed_paths(&mut self, close_tracker: &ChannelCloseTracker) {
		for record in self.records_by_id.values_mut() {
			if record.status != PaymentStatus::Pending {
				continue;
			}
			for path_idx in 0..record.paths.len() {
				let path_finished = record.blocked_paths.contains(&path_idx)
					|| record.failed_paths.contains(&path_idx);
				let path_contains_closed_channel = record.paths[path_idx]
					.iter()
					.any(|(chan_id, _, _)| close_tracker.is_closed_or_closing(chan_id));
				if path_finished || !path_contains_closed_channel {
					continue;
				}
				record.blocked_paths.insert(path_idx);
			}
		}
	}

	// Records a path-level failure event against a tracked payment, for MPP
	// accounting where individual paths can fail before the payment resolves.
	fn mark_path_failed(
		&mut self, node_idx: usize, payment_id: Option<PaymentId>, failed_path: &Path,
	) {
		// PaymentPathFailed may omit a payment id for events not tracked by
		// this harness. When it has one, match by SCID sequence, which is the
		// common representation shared between the original Route and the event.
		let Some(payment_id) = payment_id else { return };
		let Some(record) = self.records_by_id.get_mut(&payment_id) else { return };
		assert_eq!(record.source_idx, node_idx);
		if record.status != PaymentStatus::Pending {
			return;
		}
		if let Some((path_idx, _)) = record.paths.iter().enumerate().find(|(path_idx, path)| {
			!record.blocked_paths.contains(path_idx)
				&& !record.failed_paths.contains(path_idx)
				&& path.len() == failed_path.hops.len()
				&& path
					.iter()
					.zip(failed_path.hops.iter())
					.all(|((_, _, scid), hop)| *scid == hop.short_channel_id)
		}) {
			record.failed_paths.insert(path_idx);
		}
	}

	fn mark_receiver_claimed(&mut self, hash: PaymentHash) {
		if let Some(record) = self.record_for_hash_mut(&hash) {
			record.receiver_claimed = true;
		}
	}

	// Asserts no live pending payments remain: every path resolved, failed, or
	// was blocked by a close or dust.
	fn assert_no_pending(&self, context: &str) {
		let mut pending_ids = [Vec::new(), Vec::new(), Vec::new()];
		for record in self.records_by_id.values().filter(|record| {
			record.status == PaymentStatus::Pending && !record.all_paths_finished()
		}) {
			pending_ids[record.source_idx].push(record.payment_id);
		}
		for (idx, ids) in pending_ids.iter().enumerate() {
			assert!(
				ids.is_empty(),
				"Node {} has {} stuck pending payments {}: ids={:?}",
				idx,
				ids.len(),
				context,
				ids,
			);
		}
	}

	// Asserts claim_funds calls reached valid outcomes: the receiver saw
	// PaymentClaimed, and the sender either learned success or failed only
	// after every path was blocked.
	fn assert_claims_resolved(&self) {
		for record in self.records_by_id.values().filter(|record| record.claim_funds_called) {
			assert!(
				record.receiver_claimed,
				"Payment {:?} was claimed with claim_funds but receiver never got PaymentClaimed",
				record.payment_hash,
			);
			let all_paths_blocked = record.all_paths_blocked();
			match record.sender_outcome {
				Some(SenderOutcome::Sent) => {},
				Some(SenderOutcome::Failed) => assert!(
					all_paths_blocked,
					"claimed payment {:?} failed sender-side without every path blocked: \
					 blocked={:?}, failed={:?}, paths={:?}",
					record.payment_hash, record.blocked_paths, record.failed_paths, record.paths,
				),
				None => assert!(
					all_paths_blocked,
					"claimed payment {:?} never resolved sender-side: blocked={:?}, \
					 failed={:?}, paths={:?}",
					record.payment_hash, record.blocked_paths, record.failed_paths, record.paths,
				),
			}
		}
	}

	// Checks whether LDK kept outbound state for a send attempt. A payment can
	// exhaust retries immediately while committed HTLCs still need later
	// accounting.
	fn check_payment_send_events(source: &ChanMan, sent_payment_id: PaymentId) -> bool {
		for payment in source.list_recent_payments() {
			match payment {
				RecentPaymentDetails::Pending { payment_id, .. }
					if payment_id == sent_payment_id =>
				{
					return true;
				},
				RecentPaymentDetails::Abandoned { payment_id, payment_hash, .. }
					if payment_id == sent_payment_id
						&& Self::has_pending_outbound_htlc(source, payment_hash) =>
				{
					// Retries may already be exhausted even though committed HTLCs are still
					// in flight and will later resolve with PaymentFailed.
					return true;
				},
				_ => {},
			}
		}
		return false;
	}

	// Detects whether a payment hash still has committed outbound HTLCs, to
	// keep exhausted-retry payments tracked until those HTLCs resolve.
	fn has_pending_outbound_htlc(source: &ChanMan, payment_hash: PaymentHash) -> bool {
		source.list_channels().iter().any(|chan| {
			chan.pending_outbound_htlcs.iter().any(|htlc| htlc.payment_hash == payment_hash)
		})
	}

	// Creates counter-derived payment material so hand-built fuzz inputs replay
	// the same scenario. The receiver registers the hash, which yields a real
	// PaymentSecret accepted by LDK.
	fn next_payment(&mut self, dest: &ChanMan) -> (PaymentSecret, PaymentHash, PaymentId) {
		self.payment_ctr += 1;
		let mut payment_preimage = PaymentPreimage([0; 32]);
		payment_preimage.0[0..8].copy_from_slice(&self.payment_ctr.to_be_bytes());
		let hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
		let (secret, _no_metadata) = dest
			.create_inbound_payment_for_hash(hash, None, 3600, None, None)
			.expect("create_inbound_payment_for_hash failed");
		assert!(self.payment_preimages.insert(hash, payment_preimage).is_none());
		let mut id = PaymentId([0; 32]);
		id.0[0..8].copy_from_slice(&self.payment_ctr.to_ne_bytes());
		(secret, hash, id)
	}

	// Sends a single-hop payment and records it only if LDK kept outbound state.
	fn send(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize,
		dest_chan_id: ChannelId, amt: u64, close_tracker: &ChannelCloseTracker,
	) -> bool {
		if close_tracker.is_closed_or_closing(&dest_chan_id) {
			// Sending over a known-closing channel would test route construction
			// failure, not force-close cleanup.
			return false;
		}
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
			PaymentParameters::from_node_id(source.get_our_node_id(), FUZZ_FINAL_CLTV_DELTA),
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
					cltv_expiry_delta: FUZZ_FINAL_CLTV_DELTA,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			}],
			route_params: Some(route_params.clone()),
		};
		let payment_paths = vec![vec![(dest_chan_id, amt, dest_scid)]];
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
			self.register_payment(
				source_idx,
				id,
				hash,
				payment_paths,
				source.next_manager_persistence_generation(),
			);
		}
		succeeded
	}

	// Sends a two-hop payment through the middle node to cover forwarded HTLC
	// cleanup.
	fn send_hop(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, middle_idx: usize,
		middle_chan_id: ChannelId, dest_idx: usize, dest_chan_id: ChannelId, amt: u64,
		close_tracker: &ChannelCloseTracker,
	) {
		if close_tracker.is_closed_or_closing(&middle_chan_id)
			|| close_tracker.is_closed_or_closing(&dest_chan_id)
		{
			// Once either hop closes, cleanup should account for the existing
			// payment, not create a new one over the closed path.
			return;
		}
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
		let Some(dest_scid) = dest
			.list_channels()
			.iter()
			.find(|chan| chan.channel_id == dest_chan_id)
			.and_then(|chan| chan.short_channel_id)
		else {
			// The destination channel can already have disappeared due to a
			// close observed by the destination before the close tracker records
			// the topology change. Treat that as a no-op send attempt.
			return;
		};
		let first_hop_fee = 50_000;
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(source.get_our_node_id(), FUZZ_FINAL_CLTV_DELTA),
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
						cltv_expiry_delta: FUZZ_FORWARD_CLTV_DELTA,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: dest.get_our_node_id(),
						node_features: dest.node_features(),
						short_channel_id: dest_scid,
						channel_features: dest.channel_features(),
						fee_msat: amt,
						cltv_expiry_delta: FUZZ_FINAL_CLTV_DELTA,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			}],
			route_params: Some(route_params.clone()),
		};
		let payment_paths = vec![vec![
			(middle_chan_id, amt + first_hop_fee, middle_scid),
			(dest_chan_id, amt, dest_scid),
		]];
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
			self.register_payment(
				source_idx,
				id,
				hash,
				payment_paths,
				source.next_manager_persistence_generation(),
			);
		}
	}

	// Sends a direct MPP payment split across the destination channels still
	// considered live, so coverage of partially-closed MPP destinations remains.
	fn send_mpp_direct(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize,
		dest_chan_ids: &[ChannelId], amt: u64, close_tracker: &ChannelCloseTracker,
	) {
		let source = &nodes[source_idx];
		let dest = &nodes[dest_idx];
		let dest_chans = dest.list_channels();
		let dest_scids: Vec<_> = dest_chan_ids
			.iter()
			.filter(|chan_id| !close_tracker.is_closed_or_closing(chan_id))
			.filter_map(|chan_id| {
				dest_chans
					.iter()
					.find(|chan| chan.channel_id == *chan_id)
					.and_then(|chan| chan.short_channel_id)
					.map(|scid| (*chan_id, scid))
			})
			.collect();
		let num_paths = dest_scids.len();
		if num_paths == 0 {
			return;
		}
		let (secret, hash, id) = self.next_payment(dest);
		let amt_per_path = amt / num_paths as u64;
		// Build the tracked paths first and derive the Route from them so the
		// two cannot drift apart.
		let payment_paths: Vec<PaymentPath> = dest_scids
			.iter()
			.enumerate()
			.map(|(i, (chan_id, dest_scid))| {
				// The last path receives the rounding remainder.
				let path_amt = if i == num_paths - 1 {
					amt - amt_per_path * (num_paths as u64 - 1)
				} else {
					amt_per_path
				};
				vec![(*chan_id, path_amt, *dest_scid)]
			})
			.collect();
		let paths = payment_paths
			.iter()
			.map(|payment_path| {
				let (_, path_amt, dest_scid) = payment_path[0];
				Path {
					hops: vec![RouteHop {
						pubkey: dest.get_our_node_id(),
						node_features: dest.node_features(),
						short_channel_id: dest_scid,
						channel_features: dest.channel_features(),
						fee_msat: path_amt,
						cltv_expiry_delta: FUZZ_FINAL_CLTV_DELTA,
						maybe_announced_channel: true,
					}],
					blinded_tail: None,
				}
			})
			.collect();
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(dest.get_our_node_id(), FUZZ_FINAL_CLTV_DELTA),
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
			self.register_payment(
				source_idx,
				id,
				hash,
				payment_paths,
				source.next_manager_persistence_generation(),
			);
		}
	}

	// Sends a two-hop MPP payment split across the live channels on one or both
	// links. The path count is the larger live channel count; the shorter side
	// is reused round-robin so paths can be blocked independently by either hop.
	fn send_mpp_hop(
		&mut self, nodes: &[HarnessNode<'_>; 3], source_idx: usize, middle_idx: usize,
		middle_chan_ids: &[ChannelId], dest_idx: usize, dest_chan_ids: &[ChannelId], amt: u64,
		close_tracker: &ChannelCloseTracker,
	) {
		let source = &nodes[source_idx];
		let middle = &nodes[middle_idx];
		let dest = &nodes[dest_idx];
		let middle_chans = middle.list_channels();
		let middle_scids: Vec<_> = middle_chan_ids
			.iter()
			.filter(|chan_id| !close_tracker.is_closed_or_closing(chan_id))
			.filter_map(|chan_id| {
				middle_chans
					.iter()
					.find(|chan| chan.channel_id == *chan_id)
					.and_then(|chan| chan.short_channel_id)
					.map(|scid| (*chan_id, scid))
			})
			.collect();
		let dest_chans = dest.list_channels();
		let dest_scids: Vec<_> = dest_chan_ids
			.iter()
			.filter(|chan_id| !close_tracker.is_closed_or_closing(chan_id))
			.filter_map(|chan_id| {
				dest_chans
					.iter()
					.find(|chan| chan.channel_id == *chan_id)
					.and_then(|chan| chan.short_channel_id)
					.map(|scid| (*chan_id, scid))
			})
			.collect();
		if middle_scids.is_empty() || dest_scids.is_empty() {
			return;
		}
		let num_paths = middle_scids.len().max(dest_scids.len());
		let (secret, hash, id) = self.next_payment(dest);
		let first_hop_fee = 50_000;
		let amt_per_path = amt / num_paths as u64;
		let fee_per_path = first_hop_fee / num_paths as u64;
		// Build the tracked paths first and derive the Route from them so the
		// two cannot drift apart.
		let payment_paths: Vec<PaymentPath> = (0..num_paths)
			.map(|i| {
				let (middle_chan_id, middle_scid) = middle_scids[i % middle_scids.len()];
				let (dest_chan_id, dest_scid) = dest_scids[i % dest_scids.len()];
				// The last path receives the rounding remainders.
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
				vec![
					(middle_chan_id, path_amt + path_fee, middle_scid),
					(dest_chan_id, path_amt, dest_scid),
				]
			})
			.collect();
		let paths = payment_paths
			.iter()
			.map(|payment_path| {
				let (_, middle_amt, middle_scid) = payment_path[0];
				let (_, path_amt, dest_scid) = payment_path[1];
				Path {
					hops: vec![
						RouteHop {
							pubkey: middle.get_our_node_id(),
							node_features: middle.node_features(),
							short_channel_id: middle_scid,
							channel_features: middle.channel_features(),
							fee_msat: middle_amt - path_amt,
							cltv_expiry_delta: FUZZ_FORWARD_CLTV_DELTA,
							maybe_announced_channel: true,
						},
						RouteHop {
							pubkey: dest.get_our_node_id(),
							node_features: dest.node_features(),
							short_channel_id: dest_scid,
							channel_features: dest.channel_features(),
							fee_msat: path_amt,
							cltv_expiry_delta: FUZZ_FINAL_CLTV_DELTA,
							maybe_announced_channel: true,
						},
					],
					blinded_tail: None,
				}
			})
			.collect();
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(dest.get_our_node_id(), FUZZ_FINAL_CLTV_DELTA),
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
			self.register_payment(
				source_idx,
				id,
				hash,
				payment_paths,
				source.next_manager_persistence_generation(),
			);
		}
	}

	// Claims or fails a receive-side payment event.
	fn claim_payment(&mut self, node: &HarnessNode<'_>, payment_hash: PaymentHash, fail: bool) {
		if fail {
			// Fuzz bytes can choose to fail claimable payments backward,
			// preserving coverage where payments are rejected rather than
			// claimed.
			node.fail_htlc_backwards(&payment_hash);
		} else {
			// The preimage was generated by next_payment, so a missing entry
			// means LDK produced a claimable event for a payment outside the
			// harness accounting model.
			let payment_preimage = *self
				.payment_preimages
				.get(&payment_hash)
				.expect("PaymentClaimable for unknown payment hash");
			node.claim_funds(payment_preimage);
			self.record_for_hash_mut(&payment_hash)
				.expect("PaymentClaimable for unknown payment record")
				.claim_funds_called = true;
		}
	}

	// Records sender-side payment success and resolves the pending record.
	fn mark_sent(&mut self, node_idx: usize, sent_id: PaymentId, payment_hash: PaymentHash) {
		if let Some(record) = self.record_for_hash_mut(&payment_hash) {
			assert_ne!(record.sender_outcome, Some(SenderOutcome::Failed));
			record.sender_outcome = Some(SenderOutcome::Sent);
		}
		self.mark_resolved_payment(node_idx, sent_id, true);
	}

	// Records sender-side payment failure and resolves the pending record.
	fn mark_failed(
		&mut self, node_idx: usize, payment_id: PaymentId, payment_hash: Option<PaymentHash>,
	) {
		// PaymentFailed may carry the hash, but older or probe-like paths can
		// resolve by id only. Look up the hash from the record when possible so
		// sender_outcome remains tied to the same receiver-side record.
		let payment_hash = payment_hash
			.or_else(|| self.records_by_id.get(&payment_id).map(|record| record.payment_hash));
		if let Some(payment_hash) = payment_hash {
			if let Some(record) = self.record_for_hash_mut(&payment_hash) {
				assert_ne!(record.sender_outcome, Some(SenderOutcome::Sent));
				record.sender_outcome = Some(SenderOutcome::Failed);
			}
		}
		self.mark_resolved_payment(node_idx, payment_id, false);
	}

	fn mark_resolved_without_hash(&mut self, node_idx: usize, payment_id: PaymentId) {
		self.mark_resolved_payment(node_idx, payment_id, false);
	}

	// Moves a tracked payment id out of Pending. With assert_already_resolved,
	// a duplicate resolution must be Resolved rather than RolledBack.
	fn mark_resolved_payment(
		&mut self, node_idx: usize, payment_id: PaymentId, assert_already_resolved: bool,
	) {
		// Some events can arrive before the send helper records the payment,
		// especially when the payment is immediately rejected. Ignore those
		// unknown ids, except for PaymentSent where an unknown id would be a
		// tracker bug.
		let Some(record) = self.records_by_id.get_mut(&payment_id) else {
			assert!(!assert_already_resolved);
			return;
		};
		assert_eq!(record.source_idx, node_idx);
		if assert_already_resolved && record.status != PaymentStatus::Pending {
			assert_eq!(record.status, PaymentStatus::Resolved);
		}
		record.status = PaymentStatus::Resolved;
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
	close_tracker: ChannelCloseTracker,
}

fn build_node_config(chan_type: ChanType) -> UserConfig {
	let mut config = UserConfig::default();
	config.channel_config.forwarding_fee_proportional_millionths = 0;
	// Tight CLTV deltas make timeout-driven force closes reachable with short
	// fuzz inputs. These are still LDK-supported minimums, not arbitrary
	// test-only values.
	config.channel_config.cltv_expiry_delta = MIN_CLTV_EXPIRY_DELTA;
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

fn assert_no_stale_splice_negotiation(
	node: &HarnessNode<'_>, channel_id: &ChannelId, counterparty_node_id: &PublicKey, context: &str,
) {
	let Some(channel) = node.list_channels().into_iter().find(|channel| {
		channel.channel_id == *channel_id && channel.counterparty.node_id == *counterparty_node_id
	}) else {
		return;
	};
	let Some(details) = channel.splice_details else { return };

	assert!(
		details.negotiation.is_none(),
		"{} left active splice negotiation behind: {:?}",
		context,
		details
	);
	assert!(
		details.queued_contribution.is_some()
			|| !details.candidates.is_empty()
			|| details.confirmed_candidate.is_some()
			|| details.received_splice_locked_txid.is_some(),
		"{} left empty splice details behind: {:?}",
		context,
		details
	);
}

// Checks topology and broadcast invariants that should hold after cleanup.
fn assert_test_invariants(nodes: &[HarnessNode<'_>; 3], has_closed_channels: bool) {
	let channel_counts = [
		nodes[0].list_channels().len(),
		nodes[1].list_channels().len(),
		nodes[2].list_channels().len(),
	];
	if has_closed_channels {
		// Once a close is tracked, some channels may legitimately be absent from
		// list_channels. Still assert that no node ever gains channels, which
		// would indicate the harness lost track of topology.
		assert!(channel_counts[0] <= 3);
		assert!(channel_counts[1] <= 6);
		assert!(channel_counts[2] <= 3);
	} else {
		assert_eq!(channel_counts, [3, 6, 3]);
	}

	// All broadcasters should be empty because broadcast transactions only enter
	// the modeled mempool through explicit relay commands or finish cleanup.
	for node in nodes {
		assert!(node.broadcaster.txn_broadcasted.borrow().is_empty());
	}
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
	nodes: &mut [HarnessNode<'_>; 3], source_idx: usize, dest_idx: usize, chan_id: i32,
	trusted_open: bool, trusted_accept: bool, chain_state: &mut ChainState,
) {
	assert!(source_idx < dest_idx);
	let (left, right) = nodes.split_at_mut(dest_idx);
	let (source, dest) = (&mut left[source_idx], &mut right[0]);
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
			// Funding transactions are synthetic no-input transactions. The
			// version number is varied per test channel solely to make txids and
			// funding outpoints distinct.
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
			// Mine through the chain model instead of directly notifying nodes,
			// so the setup path and later force-close path share the same block
			// representation.
			chain_state.mine_setup_tx_to_depth(tx, ANTI_REORG_DELAY);
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
	dest.checkpoint_manager_persistence();
	// Complete any monitor persistence callbacks made available for dest after watch_channel.
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
	source.checkpoint_manager_persistence();
	// Complete any monitor persistence callbacks made available for source after watch_channel.
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
		let deferred = [
			config_byte & 0b0010_0000 != 0,
			config_byte & 0b0100_0000 != 0,
			config_byte & 0b1000_0000 != 0,
		];

		let wallet_a = Arc::new(TestWalletSource::new(SecretKey::from_slice(&[1; 32]).unwrap()));
		let wallet_b = Arc::new(TestWalletSource::new(SecretKey::from_slice(&[2; 32]).unwrap()));
		let wallet_c = Arc::new(TestWalletSource::new(SecretKey::from_slice(&[3; 32]).unwrap()));
		let wallets = [wallet_a.as_ref(), wallet_b.as_ref(), wallet_c.as_ref()];
		let mut chain_state = ChainState::new();
		for wallet in wallets {
			// Seed each wallet generously; anchor and splice flows need fresh
			// inputs long after setup, and an exhausted wallet would obscure the
			// close behavior under test.
			let coinbase_tx = bitcoin::Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![bitcoin::TxIn { ..Default::default() }],
				output: (0..NUM_WALLET_UTXOS)
					.map(|_| TxOut {
						value: Amount::from_sat(100_000),
						script_pubkey: wallet.get_change_script().unwrap(),
					})
					.collect(),
			};
			for vout in 0..NUM_WALLET_UTXOS {
				wallet.add_utxo(coinbase_tx.clone(), vout);
			}
			chain_state.mine_setup_tx_to_depth(coinbase_tx, ANTI_REORG_DELAY);
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
				Arc::clone(&wallet_a),
				Arc::clone(&fee_est_a),
				Arc::clone(&broadcast_a),
				persistence_styles[0],
				deferred[0],
				&out,
				router,
				chan_type,
			),
			HarnessNode::new(
				1,
				Arc::clone(&wallet_b),
				Arc::clone(&fee_est_b),
				Arc::clone(&broadcast_b),
				persistence_styles[1],
				deferred[1],
				&out,
				router,
				chan_type,
			),
			HarnessNode::new(
				2,
				Arc::clone(&wallet_c),
				Arc::clone(&fee_est_c),
				Arc::clone(&broadcast_c),
				persistence_styles[2],
				deferred[2],
				&out,
				router,
				chan_type,
			),
		];

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
		make_channel(&mut nodes, 0, 1, 1, false, false, &mut chain_state);
		make_channel(&mut nodes, 0, 1, 2, set_0reserve, set_0reserve, &mut chain_state);
		make_channel(&mut nodes, 0, 1, 3, false, set_0reserve, &mut chain_state);
		// B-C: channel 4 B has 0-reserve (via trusted accept),
		//      channel 5 C has 0-reserve (via trusted open), if channels are non-legacy.
		make_channel(&mut nodes, 1, 2, 4, false, set_0reserve, &mut chain_state);
		make_channel(&mut nodes, 1, 2, 5, set_0reserve, false, &mut chain_state);
		make_channel(&mut nodes, 1, 2, 6, false, false, &mut chain_state);

		// Wipe setup-time broadcasts so normal operation starts with an empty
		// relay queue; the setup funding is already represented in ChainState.
		for node in &nodes {
			node.broadcaster.txn_broadcasted.borrow_mut().clear();
		}
		for node in &mut nodes {
			// Sync every node to the funding depth before channel_ready exchange
			// so all channels start from the same confirmed chain view.
			node.sync_with_chain_state(&chain_state, None);
		}

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
			node.force_checkpoint_manager_persistence();
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
			close_tracker: ChannelCloseTracker::new(),
		}
	}

	fn chan_a_id(&self) -> ChannelId {
		self.ab_link.first_channel_id()
	}

	fn chan_b_id(&self) -> ChannelId {
		self.bc_link.first_channel_id()
	}

	// Runs end-of-input cleanup by relaying and mining remaining broadcasts.
	// Final invariants should not depend on the input ending with explicit relay
	// and mining bytes.
	fn finish(&mut self) {
		self.mine_relayed_txs_until_quiet("finish");
		self.record_disappeared_channels();
		self.assert_no_unexpected_channel_closes();
		let has_closed_channels = self.close_tracker.has_closed_channels();
		assert_test_invariants(&self.nodes, has_closed_channels);
	}

	// Checks both peer links for unintended sibling-channel closes.
	fn assert_no_unexpected_channel_closes(&self) {
		self.ab_link.assert_no_unexpected_channel_closes(&self.nodes, &self.close_tracker);
		self.bc_link.assert_no_unexpected_channel_closes(&self.nodes, &self.close_tracker);
	}

	// Records closes visible only as channels missing from list_channels, which
	// can happen before, or instead of, ChannelClosed event processing.
	fn record_disappeared_channels(&mut self) {
		self.ab_link.record_disappeared_channels(&self.nodes, &mut self.close_tracker);
		self.bc_link.record_disappeared_channels(&self.nodes, &mut self.close_tracker);
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

	fn send(&mut self, source_idx: usize, dest_idx: usize, amt: u64) {
		let dest_chan_id = self.first_channel_id_between(source_idx, dest_idx);
		self.payments.send(
			&self.nodes,
			source_idx,
			dest_idx,
			dest_chan_id,
			amt,
			&self.close_tracker,
		);
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
			&self.close_tracker,
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
					&self.close_tracker,
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
					&self.close_tracker,
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
					&self.close_tracker,
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
					&self.close_tracker,
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
					&self.close_tracker,
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
			chain_state: &ChainState, close_tracker: &ChannelCloseTracker, out: &Out,
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
					if close_tracker.is_closed_or_closing(&msg.channel_id) {
						// A delayed reestablish for a closing channel is stale
						// traffic that would only manufacture a second error path
						// for the same close.
						return None;
					}
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
					assert_no_stale_splice_negotiation(
						&nodes[dest_idx],
						&msg.channel_id,
						&source_node_id,
						"tx_abort receive",
					);
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
					assert!(
						chain_state.is_confirmed_txid(&msg.splice_txid),
						"splice_locked referenced unconfirmed txid {}",
						msg.splice_txid
					);
					nodes[dest_idx].handle_splice_locked(source_node_id, msg);
					None
				},
				MessageSendEvent::HandleError { ref action, ref node_id } => {
					close_tracker.assert_expected_control_error_action(action);
					match action {
						msgs::ErrorAction::DisconnectPeerWithWarning { msg } => {
							let dest_idx =
								log_peer_message(node_idx, node_id, nodes, out, "warning");
							if is_quiescent_disconnect_warning(msg) {
								// Splice quiescence warnings are recovery signals,
								// not closes; exit quiescence on both peers.
								nodes[node_idx]
									.node
									.exit_quiescence(node_id, &msg.channel_id)
									.unwrap();
								nodes[dest_idx]
									.node
									.exit_quiescence(&source_node_id, &msg.channel_id)
									.unwrap();
							}
						},
						msgs::ErrorAction::SendErrorMessage { msg } => {
							// Deliver the error so the counterparty observes the
							// close the same way it would over the wire.
							let dest_idx = log_peer_message(node_idx, node_id, nodes, out, "error");
							nodes[dest_idx].handle_error(source_node_id, msg);
						},
						_ => unreachable!(),
					}
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
		let chain_state = &self.chain_state;
		let out = &self.out;
		let queues = &mut self.queues;
		let close_tracker = &self.close_tracker;
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
				chain_state,
				close_tracker,
				out,
			);
			if limit_events != ProcessMessages::AllMessages {
				break;
			}
		}
		if node_idx == 1 {
			let remaining = extra_ev.into_iter().chain(events_iter).collect::<Vec<_>>();
			queues.route_from_middle(remaining, None, nodes, close_tracker);
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

	// Drains user-facing events from one node and updates harness accounting.
	fn process_events(&mut self, node_idx: usize, fail: bool) -> bool {
		let nodes = &self.nodes;
		let payments = &mut self.payments;
		let chain_state = &self.chain_state;
		let close_tracker = &mut self.close_tracker;
		// Multiple HTLCs can resolve for the same payment hash, so deduplicate
		// claim/fail handling per event batch.
		let mut claim_set = new_hash_map();
		let mut events = nodes[node_idx].get_and_clear_pending_events();
		let mut had_events = !events.is_empty();
		for event in events.drain(..) {
			match event {
				events::Event::PaymentClaimable { payment_hash, claim_deadline, .. } => {
					if claim_deadline
						.map_or(false, |deadline| nodes[node_idx].manager_height() >= deadline)
					{
						// Past the claim_deadline, claim_funds is outside its API
						// contract; let LDK's timeout fail-back resolve the payment.
						continue;
					}
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
					payments.mark_resolved_without_hash(node_idx, payment_id);
				},
				events::Event::PaymentFailed { payment_id, payment_hash, .. } => {
					payments.mark_failed(node_idx, payment_id, payment_hash);
				},
				events::Event::ProbeFailed { payment_id, .. } => {
					payments.mark_resolved_without_hash(node_idx, payment_id);
				},
				events::Event::PaymentClaimed { payment_hash, .. } => {
					payments.mark_receiver_claimed(payment_hash);
				},
				events::Event::PaymentPathSuccessful { .. } => {},
				events::Event::PaymentPathFailed { payment_id, path, .. } => {
					payments.mark_path_failed(node_idx, payment_id, &path);
				},
				events::Event::PaymentForwarded { .. } if node_idx == 1 => {},
				events::Event::ChannelReady { funding_txo, .. } => {
					if let Some(funding_txo) = funding_txo {
						assert!(
							chain_state.is_confirmed_txid(&funding_txo.txid),
							"ChannelReady referenced unconfirmed funding txid {}",
							funding_txo.txid
						);
					}
				},
				events::Event::HTLCHandlingFailed {
					failure_type: events::HTLCHandlingFailureType::Receive { payment_hash },
					..
				} => {
					assert!(
						!payments.claim_funds_called(&payment_hash),
						"Payment {:?} hit HTLCHandlingFailed::Receive after claim_funds",
						payment_hash,
					);
				},
				events::Event::HTLCHandlingFailed { .. } => {},
				events::Event::FundingTransactionReadyForSigning {
					channel_id,
					counterparty_node_id,
					unsigned_transaction,
					..
				} => {
					let wallet_script = nodes[node_idx].wallet.get_change_script().unwrap();
					let has_unknown_spent_input = unsigned_transaction.input.iter().any(|input| {
						!chain_state.is_unspent(&input.previous_output)
							&& chain_state.confirmed_output(&input.previous_output).is_none()
					});
					assert!(
						!has_unknown_spent_input,
						"funding transaction referenced an unmodeled input: {:?}",
						unsigned_transaction,
					);
					let has_spent_wallet_input = unsigned_transaction.input.iter().any(|input| {
						!chain_state.is_unspent(&input.previous_output)
							&& chain_state
								.confirmed_output(&input.previous_output)
								.map_or(false, |output| output.script_pubkey == wallet_script)
					});
					if has_spent_wallet_input {
						// A queued RBF signing request can lose the race against a
						// transaction confirming with one of its wallet inputs.
						match nodes[node_idx]
							.cancel_funding_contributed(&channel_id, &counterparty_node_id)
						{
							Ok(()) => {},
							Err(APIError::APIMisuseError { ref err })
								if err.contains("does not have a pending splice negotiation") => {},
							Err(e) => panic!("{e:?}"),
						}
					} else {
						let signed_tx =
							nodes[node_idx].wallet.sign_tx(unsigned_transaction).unwrap();
						match nodes[node_idx].funding_transaction_signed(
							&channel_id,
							&counterparty_node_id,
							signed_tx,
						) {
							Ok(()) => {},
							Err(APIError::APIMisuseError { ref err })
								if err.contains("not expecting funding signatures") =>
							{
								// A queued signing event can be invalidated by a later `tx_abort`
								// before the application handles it.
							},
							Err(e) => panic!("{e:?}"),
						}
					}
				},
				events::Event::SpliceNegotiated { .. } => {
					// LDK already broadcast the new funding transaction; relay and
					// mining commands decide when it confirms.
				},
				events::Event::SpliceNegotiationFailed { .. } => {},
				events::Event::ChannelClosed { channel_id, reason, .. } => {
					close_tracker.record_channel_closed_event(channel_id, &reason);
					// Dust HTLCs on the closed channel can never produce an
					// on-chain claim, so block their paths up front.
					payments.block_dust_paths_containing_channel(
						channel_id,
						MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS as u64 * 1000,
					);
					if let events::ClosureReason::HTLCsTimedOut {
						payment_hash: Some(payment_hash),
					} = reason
					{
						// The timeout close names the affected payment, so only
						// its paths through the closed channel are blocked.
						payments.block_paths_containing_channel(&payment_hash, channel_id);
					}
				},
				events::Event::DiscardFunding { .. } => {},
				events::Event::SpendableOutputs { .. } => {
					// This target tracks wallet UTXOs from confirmed
					// wallet-owned transaction outputs. It does not sweep LDK
					// spendable outputs.
				},
				events::Event::BumpTransaction(bump) => {
					nodes[node_idx].bump_tx_handler.handle_event(&bump);
				},
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

	// Drives event and message processing until the harness is quiet.
	fn process_all_events(&mut self) {
		let settled = self.progress_until_quiet(MAX_SETTLE_ITERATIONS);
		assert!(settled, "process_all_events exceeded settle budget");
	}

	// Finds the earliest loaded monitor height for a node. Startup sync uses it
	// as ChainMonitor's start height so raw monitors loaded below the manager's
	// best block still see every block and transaction they missed.
	fn oldest_monitor_height_for_node(&self, node_idx: usize) -> u32 {
		let node = &self.nodes[node_idx];
		let mut min_monitor_height = node.manager_height();
		for chan_id in node.monitor.list_monitors() {
			if let Ok(mon) = node.monitor.get_monitor(chan_id) {
				min_monitor_height = cmp::min(min_monitor_height, mon.current_best_block().height);
			}
		}
		min_monitor_height
	}

	// Restarts one node from a fuzz-selected persisted state, updating payment
	// records the reloaded manager can no longer remember.
	fn restart_node(&mut self, node_idx: usize, v: u8, router: &'a FuzzRouter) {
		if !self.nodes[node_idx].deferred {
			self.nodes[node_idx].checkpoint_manager_persistence();
		}
		match node_idx {
			0 => {
				self.ab_link.disconnect_for_reload(
					0,
					&self.nodes,
					&mut self.queues,
					&self.close_tracker,
				);
			},
			1 => {
				self.ab_link.disconnect_for_reload(
					1,
					&self.nodes,
					&mut self.queues,
					&self.close_tracker,
				);
				self.bc_link.disconnect_for_reload(
					1,
					&self.nodes,
					&mut self.queues,
					&self.close_tracker,
				);
			},
			2 => {
				self.bc_link.disconnect_for_reload(
					2,
					&self.nodes,
					&mut self.queues,
					&self.close_tracker,
				);
			},
			_ => panic!("invalid node index"),
		}
		let loaded_manager_generation =
			self.nodes[node_idx].reload(v, &self.out, router, self.chan_type);
		let monitor_start_height = self.oldest_monitor_height_for_node(node_idx);
		let manager_start_height = self.nodes[node_idx].manager_height();
		// Startup sync is part of LDK's deserialization contract.
		self.nodes[node_idx].connect_chain_range(
			&self.chain_state,
			monitor_start_height,
			manager_start_height,
			self.chain_state.tip_height(),
		);
		assert_eq!(
			self.nodes[node_idx].manager_height(),
			self.chain_state.tip_height(),
			"reloaded node {} must sync to the harness tip before normal operation resumes",
			node_idx
		);
		let rolled_back_payment_hashes =
			self.payments.sync_pending_with_manager_generation(node_idx, loaded_manager_generation);
		for payment_hash in rolled_back_payment_hashes {
			// If a reload rolled back a manager past claim_funds, the harness
			// must not require the reloaded manager to later report
			// PaymentClaimed for that claim.
			self.payments.clear_claim(&payment_hash);
		}
	}

	// Drives the whole harness toward settlement and checks final invariants.
	fn settle_all(&mut self) {
		// The cleanup invariants are about eventual resolution, so undo any
		// fuzzer-selected disconnections first.
		self.reconnect_ab();
		self.reconnect_bc();

		for op in SUPPORTED_SIGNER_OPS {
			// Re-enable all signer ops so failures after this point indicate
			// missing event, chain, or accounting progress rather than an
			// intentionally blocked signer.
			self.nodes[0].keys_manager.enable_op_for_all_signers(op);
			self.nodes[1].keys_manager.enable_op_for_all_signers(op);
			self.nodes[2].keys_manager.enable_op_for_all_signers(op);
		}
		// Live-channel signer work retries through the manager, while
		// on-chain holder claims retry through the chain monitor.
		self.nodes[0].signer_unblocked(None);
		self.nodes[1].signer_unblocked(None);
		self.nodes[2].signer_unblocked(None);
		self.nodes[0].monitor.signer_unblocked(None);
		self.nodes[1].monitor.signer_unblocked(None);
		self.nodes[2].monitor.signer_unblocked(None);

		self.process_all_events();

		// Since MPP payments are supported, we wait until we fully settle the state of all
		// channels to see if we have any committed HTLC parts of an MPP payment that need
		// to be failed back.
		for node in self.nodes.iter() {
			node.timer_tick_occurred();
		}
		self.process_all_events();

		if self.close_tracker.has_closed_channels() {
			for _ in 0..FORCE_CLOSE_CLEANUP_ROUNDS {
				// Force-close cleanup alternates between event/message progress
				// and height progress. This mirrors real nodes, where blocks
				// trigger monitor claims, those claims broadcast transactions,
				// and later blocks confirm the resulting transactions.
				self.flush_progress(QUIESCENCE_ROUNDS);
				for node in self.nodes.iter() {
					node.timer_tick_occurred();
				}
				self.flush_progress(QUIESCENCE_ROUNDS);
				let balances = self.claimable_balances();
				let has_pending_htlcs = self.has_pending_htlcs();
				// Payment work can be waiting in the tracker or still committed
				// in live channel HTLC state. Chain work can be waiting in
				// claimable balances, broadcasts, the mempool, monitor updates,
				// or those same HTLCs. Keep the two signals separate so the loop
				// mines only when there is both something to finish and some
				// modeled mechanism that could still advance it.
				let needs_payment_completion =
					self.payments.has_live_payment_work() || has_pending_htlcs;
				let has_cleanup_balances = !balances.is_empty();
				let can_drive_more_cleanup =
					has_cleanup_balances || self.has_pending_work() || has_pending_htlcs;
				let next_claimed_htlc_boundary = self.next_claimed_htlc_boundary(&balances);
				// This only gates the explicit height advance below; progress
				// rounds can still mine to confirm transactions already in the
				// mempool.
				let can_advance_without_claimed_expiry = next_claimed_htlc_boundary
					.map_or(true, |boundary| {
						self.chain_state.tip_height().saturating_add(1) < boundary
					});
				if !needs_payment_completion || !can_drive_more_cleanup {
					// Either all payment work is accounted for, or there is no
					// remaining event, transaction, balance, or HTLC state that
					// could make another cleanup round useful.
					break;
				}
				if self.payments.has_unfinished_claims() && !can_advance_without_claimed_expiry {
					// Stop before mining across a claimed HTLC expiry that
					// still needs sender-side resolution. Crossing that boundary
					// would turn a useful payment-accounting invariant into a
					// race against this final cleanup driver.
					break;
				}
				self.mine_blocks(1);
				self.flush_progress(QUIESCENCE_ROUNDS);
			}
		}

		self.payments.block_unresolvable_closed_paths(&self.close_tracker);
		self.payments.assert_no_pending("after settling all state");
		self.payments.assert_claims_resolved();

		// All HTLCs should have been claimed or failed once we reach quiescence.
		for (idx, node) in self.nodes.iter().enumerate() {
			for chan in node.list_channels() {
				if self.close_tracker.is_closed_or_closing(&chan.channel_id) {
					continue;
				}
				let inbound_hashes = chan
					.pending_inbound_htlcs
					.iter()
					.map(|htlc| htlc.payment_hash)
					.collect::<Vec<_>>();
				let outbound_hashes = chan
					.pending_outbound_htlcs
					.iter()
					.map(|htlc| htlc.payment_hash)
					.collect::<Vec<_>>();
				assert!(
					chan.pending_inbound_htlcs.is_empty() && chan.pending_outbound_htlcs.is_empty(),
					"Node {} channel {:?} has stuck HTLCs after settling all state: \
					 inbound_hashes={:?}, outbound_hashes={:?}, {} inbound {:?}, {} outbound {:?}",
					idx,
					chan.channel_id,
					inbound_hashes,
					outbound_hashes,
					chan.pending_inbound_htlcs.len(),
					chan.pending_inbound_htlcs,
					chan.pending_outbound_htlcs.len(),
					chan.pending_outbound_htlcs
				);
			}
		}

		self.ab_link.complete_all_monitor_updates(&self.nodes);
		self.bc_link.complete_all_monitor_updates(&self.nodes);
		self.record_disappeared_channels();
		// Check both close-tracker and topology-level invariants. The close
		// tracker verifies every observed close became expected; the peer links
		// verify every non-closed sibling channel is still listed by both peers.
		self.close_tracker.assert_no_unexpected_channel_closes();
		self.assert_no_unexpected_channel_closes();

		// Every still-open channel must be able to send in at least one
		// direction; closed channels are validated by close accounting instead.
		for (node_a, node_b, channel_ids) in
			[(0, 1, *self.ab_link.channel_ids()), (1, 2, *self.bc_link.channel_ids())]
		{
			for chan_id in channel_ids {
				if self.close_tracker.is_closed_or_closing(&chan_id) {
					continue;
				}
				self.assert_sendable_after_settle(node_a, node_b, chan_id);
			}
		}

		self.process_all_events();
		self.payments.assert_no_pending("after settle probes");

		self.nodes[0].record_last_htlc_clear_fee();
		self.nodes[1].record_last_htlc_clear_fee();
		self.nodes[2].record_last_htlc_clear_fee();
	}

	fn checkpoint_manager_persistences(&mut self) -> bool {
		let mut made_progress = false;
		for node in &mut self.nodes {
			made_progress |= node.checkpoint_manager_persistence();
		}
		made_progress
	}

	// Relays one node's broadcasts into the mempool. Per-node relay lets fuzz
	// inputs model partial propagation before a block is mined.
	fn relay_broadcasts_for_node(&mut self, node_idx: usize) {
		let txs = self.nodes[node_idx]
			.broadcaster
			.txn_broadcasted
			.borrow_mut()
			.drain(..)
			.collect::<Vec<_>>();
		self.chain_state.relay_transactions(txs);
	}

	// Relays every node's pending broadcasts into the modeled mempool. Cleanup
	// uses this when it should not depend on which peer fuzz bytes propagate.
	// The bool reports whether any broadcasts were drained, not whether they
	// were all admitted.
	fn relay_all_broadcasts(&mut self) -> bool {
		let mut txs = Vec::new();
		for node in &self.nodes {
			txs.extend(node.broadcaster.txn_broadcasted.borrow_mut().drain(..));
		}
		self.chain_state.relay_transactions(txs)
	}

	// Mines blocks through ChainState, applies confirmed transactions to the
	// wallets, and syncs node chain listeners.
	fn mine_blocks(&mut self, count: u32) {
		assert!(count > 0, "mining zero blocks should not be requested");

		let confirmed_txs = self.chain_state.mine_blocks(count);
		let wallets = [
			self.nodes[0].wallet.as_ref(),
			self.nodes[1].wallet.as_ref(),
			self.nodes[2].wallet.as_ref(),
		];
		for tx in &confirmed_txs {
			for wallet in wallets.iter().copied() {
				let change_script = wallet.get_change_script().unwrap();
				for input in &tx.input {
					// The test wallet is a simple UTXO source. When one of its
					// outputs is spent by a confirmed transaction, remove it so
					// later funding or bump attempts cannot double-spend it.
					wallet.remove_utxo(input.previous_output);
				}
				for (vout, output) in tx.output.iter().enumerate() {
					if output.script_pubkey == change_script {
						// Confirmed wallet-owned outputs become new wallet
						// inputs, letting anchor and splice flows reuse change
						// through later fuzz commands.
						wallet.add_utxo(tx.clone(), vout as u32);
					}
				}
			}
		}
		self.sync_all_nodes_with_chain_state();
	}

	// Repeatedly relays broadcasts and mines pending transactions to depth, for
	// finish and settle paths where confirmed claims may broadcast child
	// transactions that also need confirmation.
	fn mine_relayed_txs_until_quiet(&mut self, context: &str) {
		for _ in 0..QUIESCENCE_ROUNDS {
			self.relay_all_broadcasts();
			if !self.chain_state.has_pending_txs() {
				return;
			}
			self.mine_blocks(ANTI_REORG_DELAY);
		}
		assert!(
			!self.nodes.iter().any(|node| !node.broadcaster.txn_broadcasted.borrow().is_empty())
				&& !self.chain_state.has_pending_txs(),
			"{context} tx mining loop failed to quiesce",
		);
	}

	// Collects claimable balances from the monitors of closed channels, to know
	// when on-chain funds still require more blocks, transactions, or monitor
	// work.
	fn claimable_balances(&self) -> Vec<Balance> {
		// get_claimable_balances skips monitors whose channel appears in the
		// ignored list, so passing every open channel returns balances only for
		// closed channels.
		let open_channels = self.nodes[0]
			.node
			.list_channels()
			.iter()
			.chain(self.nodes[1].node.list_channels().iter())
			.chain(self.nodes[2].node.list_channels().iter())
			.cloned()
			.collect::<Vec<_>>();
		let open_refs: Vec<_> = open_channels.iter().collect();
		self.nodes.iter().flat_map(|node| node.monitor.get_claimable_balances(&open_refs)).collect()
	}

	// Reports whether any monitor persistence completion is still pending; these
	// can block claim generation even when no peer messages are queued.
	fn has_pending_monitor_updates(&self) -> bool {
		self.nodes.iter().any(|node| {
			node.persister
				.latest_monitors
				.lock()
				.unwrap()
				.values()
				.any(|state| !state.pending_monitor_completions.is_empty())
		})
	}

	// Finds the nearest HTLC claim or expiry boundary for a claim that still
	// needs sender-side resolution. Crossing such a boundary can change the
	// failure mode the harness observes, so settlement stops mining before it.
	fn next_claimed_htlc_boundary(&self, balances: &[Balance]) -> Option<u32> {
		balances
			.iter()
			.filter_map(|balance| {
				let (height, payment_hash) = match balance {
					Balance::ContentiousClaimable { timeout_height, payment_hash, .. } => {
						(*timeout_height, payment_hash)
					},
					Balance::MaybeTimeoutClaimableHTLC {
						claimable_height, payment_hash, ..
					} => (*claimable_height, payment_hash),
					Balance::MaybePreimageClaimableHTLC { expiry_height, payment_hash, .. } => {
						(*expiry_height, payment_hash)
					},
					_ => return None,
				};
				// Boundaries only matter for claims whose sender side has not
				// resolved and whose paths are not all already blocked.
				let claim_needs_sender_resolution = self
					.payments
					.record_for_hash(payment_hash)
					.map(|record| {
						record.claim_funds_called
							&& record.sender_outcome.is_none()
							&& !record.all_paths_blocked()
					})
					.unwrap_or(false);
				claim_needs_sender_resolution.then_some(height)
			})
			.min()
	}

	// Checks whether any modeled subsystem still has work to do: queued
	// messages, broadcasts, mempool entries, monitor updates, or claimable
	// balances.
	fn has_pending_work(&self) -> bool {
		!self.queues.ab.is_empty()
			|| !self.queues.ba.is_empty()
			|| !self.queues.bc.is_empty()
			|| !self.queues.cb.is_empty()
			|| self.chain_state.has_pending_txs()
			|| self.nodes.iter().any(|node| !node.broadcaster.txn_broadcasted.borrow().is_empty())
			|| self.has_pending_monitor_updates()
			|| !self.claimable_balances().is_empty()
	}

	// Checks live channels for unresolved HTLCs.
	fn has_pending_htlcs(&self) -> bool {
		self.nodes.iter().any(|node| {
			node.list_channels().iter().any(|chan| {
				!chan.pending_inbound_htlcs.is_empty() || !chan.pending_outbound_htlcs.is_empty()
			})
		})
	}

	// Completes any deferred monitor updates so fuzzed persistence delay does
	// not block cleanup.
	fn complete_pending_monitor_updates(&self) -> bool {
		let mut completed_monitor_update = false;
		for id in self.ab_link.channel_ids() {
			completed_monitor_update |= self.nodes[0].complete_all_monitor_updates(id);
			completed_monitor_update |= self.nodes[1].complete_all_monitor_updates(id);
		}
		for id in self.bc_link.channel_ids() {
			completed_monitor_update |= self.nodes[1].complete_all_monitor_updates(id);
			completed_monitor_update |= self.nodes[2].complete_all_monitor_updates(id);
		}
		completed_monitor_update
	}

	// Syncs every harness node to the current ChainState tip.
	fn sync_all_nodes_with_chain_state(&mut self) {
		for idx in 0..self.nodes.len() {
			self.sync_node_with_chain_state(idx, None);
		}
	}

	// Syncs one node toward the ChainState tip, first pre-authorizing the
	// timeout closes LDK may perform while connecting the blocks.
	fn sync_node_with_chain_state(&mut self, node_idx: usize, num_blocks: Option<u32>) {
		let target_height = if let Some(num_blocks) = num_blocks {
			std::cmp::min(
				self.nodes[node_idx].manager_height().saturating_add(num_blocks),
				self.chain_state.tip_height(),
			)
		} else {
			self.chain_state.tip_height()
		};
		self.allow_htlc_timeout_closes_for_node(node_idx, target_height);
		self.nodes[node_idx].sync_with_chain_state(&self.chain_state, num_blocks);
	}

	// Marks channels whose HTLCs allow LDK to force-close at the target height,
	// mirroring the monitor's timeout conditions: an outbound HTLC past expiry
	// by the grace period, or an inbound HTLC near expiry whose preimage the
	// node may have learned through a claim. The monitor only knows a preimage
	// after claim_funds, so checking the claim keeps this allowance close to
	// what LDK can actually do.
	fn allow_htlc_timeout_closes_for_node(&mut self, node_idx: usize, target_height: u32) {
		for chan in self.nodes[node_idx].list_channels() {
			let outbound_timed_out = chan.pending_outbound_htlcs.iter().any(|htlc| {
				htlc.cltv_expiry.saturating_add(HTLC_TIMEOUT_GRACE_BLOCKS) <= target_height
			});
			let inbound_timed_out = chan.pending_inbound_htlcs.iter().any(|htlc| {
				htlc.cltv_expiry <= target_height.saturating_add(HTLC_CLAIM_BUFFER_BLOCKS)
					&& self.payments.claim_funds_called(&htlc.payment_hash)
			});
			if outbound_timed_out || inbound_timed_out {
				self.close_tracker.expect_channel_close(chan.channel_id);
			}
		}
	}

	// Drains monitor-generated events on every node; monitors can enqueue claim
	// work independently of peer messages.
	fn process_monitor_pending_events(&self) {
		for node in &self.nodes {
			node.process_monitor_pending_events();
		}
	}

	// Runs one cleanup pass and reports whether anything advanced.
	fn progress_round(&mut self) -> bool {
		let made_progress = self.checkpoint_manager_persistences();
		let completed_monitor_update = self.complete_pending_monitor_updates();
		let mut had_msg_or_ev = false;
		for node_idx in 0..3 {
			if self.process_msg_events(node_idx, false, ProcessMessages::AllMessages) {
				had_msg_or_ev = true;
			}
		}
		for node_idx in 0..3 {
			if self.process_events(node_idx, false) {
				had_msg_or_ev = true;
			}
		}
		let relayed_before_mining = self.relay_all_broadcasts();
		let mined_txs = self.chain_state.has_pending_txs();
		if mined_txs {
			// Mine mempool transactions deeply enough for confirmation-sensitive
			// logic to run in the same progress round.
			self.mine_blocks(ANTI_REORG_DELAY);
		}
		self.process_monitor_pending_events();
		let relayed_after_mining = self.relay_all_broadcasts();
		made_progress
			|| completed_monitor_update
			|| relayed_before_mining
			|| relayed_after_mining
			|| mined_txs || had_msg_or_ev
	}

	// Repeats progress rounds until two consecutive quiet passes, since one
	// drain can expose work that is only visible on the next pass.
	fn progress_until_quiet(&mut self, max_iters: usize) -> bool {
		let mut last_pass_no_updates = false;
		for _ in 0..max_iters {
			if self.progress_round() {
				last_pass_no_updates = false;
				continue;
			}
			if last_pass_no_updates {
				return true;
			}
			last_pass_no_updates = true;
		}
		false
	}

	// Drains immediately processable work and asserts if that work keeps making
	// progress past the iteration budget. Height-gated work may remain for the
	// caller to handle by mining another block.
	fn flush_progress(&mut self, max_iters: usize) {
		let settled = self.progress_until_quiet(max_iters);
		let pending_work = self.has_pending_work();
		assert!(
			!pending_work || settled,
			"flush_progress exhausted {max_iters} iterations without quiescing",
		);
	}

	fn disconnect_ab(&mut self) {
		self.ab_link.disconnect(&self.nodes, &mut self.queues, &self.close_tracker);
	}

	fn disconnect_bc(&mut self) {
		self.bc_link.disconnect(&self.nodes, &mut self.queues, &self.close_tracker);
	}

	fn reconnect_ab(&mut self) {
		self.ab_link.reconnect(&self.nodes);
	}

	fn reconnect_bc(&mut self) {
		self.bc_link.reconnect(&self.nodes);
	}

	// Force-closes one channel, recording the expected close before calling
	// into LDK so the invariants reject any other channel loss.
	fn force_close(
		&mut self, closer_idx: usize, channel_id: ChannelId, counterparty_idx: usize, reason: &str,
	) {
		self.close_tracker.expect_channel_close(channel_id);
		let _ = self.nodes[closer_idx].node.force_close_broadcasting_latest_txn(
			&channel_id,
			&self.nodes[counterparty_idx].get_our_node_id(),
			reason.to_string(),
		);
	}

	// Chooses a post-settle probe amount for one direction, clamping the
	// historical 10_000_000 msat probe into the channel's current sendable
	// range after fees, reserves, or force-close cleanup changed it.
	fn probe_amount_for_direction(
		&self, source_idx: usize, dest_chan_id: ChannelId,
	) -> Option<u64> {
		self.nodes[source_idx]
			.node
			.list_usable_channels()
			.iter()
			.find(|chan| chan.channel_id == dest_chan_id)
			.and_then(|chan| {
				let probe_amt = cmp::max(
					cmp::min(10_000_000, chan.next_outbound_htlc_limit_msat),
					chan.next_outbound_htlc_minimum_msat,
				);
				if probe_amt == 0 || probe_amt > chan.next_outbound_htlc_limit_msat {
					None
				} else {
					Some(probe_amt)
				}
			})
	}

	// Asserts a surviving channel can still route a payment in at least one
	// direction after settlement.
	fn assert_sendable_after_settle(&mut self, node_a: usize, node_b: usize, chan_id: ChannelId) {
		let sent =
			[(node_a, node_b), (node_b, node_a)].into_iter().any(|(source_idx, dest_idx)| {
				let Some(amt) = self.probe_amount_for_direction(source_idx, chan_id) else {
					return false;
				};
				self.payments.send(
					&self.nodes,
					source_idx,
					dest_idx,
					chan_id,
					amt,
					&self.close_tracker,
				)
			});
		assert!(sent, "channel {:?} cannot send in either direction after settling", chan_id);
	}
}

#[inline]
pub fn do_test<Out: Output + MaybeSend + MaybeSync>(data: &[u8], out: Out) {
	let router = FuzzRouter {};
	// Read initial monitor styles, channel type, and deferred write mode from fuzz input byte 0:
	// bits 0-2: monitor styles (1 bit per node)
	// bits 3-4: channel type (0=Legacy, 1=KeyedAnchors, 2=ZeroFeeCommitments)
	// bits 5-7: deferred monitor write mode (1 bit per node)
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

			0x90 => {
				harness.nodes[0].checkpoint_manager_persistence();
			},
			0x91 => {
				harness.nodes[1].checkpoint_manager_persistence();
			},
			0x92 => {
				harness.nodes[2].checkpoint_manager_persistence();
			},

			0xa0 => {
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[0].splice_in(&cp_node_id, &harness.chan_a_id());
			},
			0xa1 => {
				let cp_node_id = harness.nodes[0].get_our_node_id();
				harness.nodes[1].splice_in(&cp_node_id, &harness.chan_a_id());
			},
			0xa2 => {
				let cp_node_id = harness.nodes[2].get_our_node_id();
				harness.nodes[1].splice_in(&cp_node_id, &harness.chan_b_id());
			},
			0xa3 => {
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[2].splice_in(&cp_node_id, &harness.chan_b_id());
			},

			0xa4 => {
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[0].splice_out(&cp_node_id, &harness.chan_a_id());
			},
			0xa5 => {
				let cp_node_id = harness.nodes[0].get_our_node_id();
				harness.nodes[1].splice_out(&cp_node_id, &harness.chan_a_id());
			},
			0xa6 => {
				let cp_node_id = harness.nodes[2].get_our_node_id();
				harness.nodes[1].splice_out(&cp_node_id, &harness.chan_b_id());
			},
			0xa7 => {
				let cp_node_id = harness.nodes[1].get_our_node_id();
				harness.nodes[2].splice_out(&cp_node_id, &harness.chan_b_id());
			},

			// Sync node by 1 block.
			0xa8 => harness.sync_node_with_chain_state(0, Some(1)),
			0xa9 => harness.sync_node_with_chain_state(1, Some(1)),
			0xaa => harness.sync_node_with_chain_state(2, Some(1)),
			// Sync node to chain tip.
			0xab => harness.sync_node_with_chain_state(0, None),
			0xac => harness.sync_node_with_chain_state(1, None),
			0xad => harness.sync_node_with_chain_state(2, None),

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
			0xcf => {
				harness.nodes[0]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignSpliceSharedInput);
				harness.nodes[0].signer_unblocked(None);
			},
			0xd0 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignSpliceSharedInput);
				let filter = Some((harness.nodes[0].get_our_node_id(), harness.chan_a_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xd1 => {
				harness.nodes[1]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignSpliceSharedInput);
				let filter = Some((harness.nodes[2].get_our_node_id(), harness.chan_b_id()));
				harness.nodes[1].signer_unblocked(filter);
			},
			0xd2 => {
				harness.nodes[2]
					.keys_manager
					.enable_op_for_all_signers(SignerOp::SignSpliceSharedInput);
				harness.nodes[2].signer_unblocked(None);
			},
			// The harness toggles signer availability at node granularity, not
			// per channel, so each byte re-enables both holder claim ops and
			// asks that node's monitors to retry.
			0xd3 => harness.nodes[0].enable_holder_signer_ops(),
			0xd4 => harness.nodes[1].enable_holder_signer_ops(),
			0xd5 => harness.nodes[2].enable_holder_signer_ops(),
			0xd6 => harness.relay_broadcasts_for_node(0),
			0xd7 => harness.relay_broadcasts_for_node(1),
			0xd8 => harness.relay_broadcasts_for_node(2),
			0xd9..=0xe0 => {
				let count = MINE_BLOCK_COUNTS[(v - 0xd9) as usize];
				harness.mine_blocks(count);
			},
			// Explicit force closes cover both directions on both peer links.
			// Each command records exactly one expected channel close before
			// calling into LDK.
			0xe1 => harness.force_close(0, harness.chan_a_id(), 1, FORCE_CLOSE_ERROR_MESSAGES[0]),
			0xe2 => harness.force_close(1, harness.chan_b_id(), 2, FORCE_CLOSE_ERROR_MESSAGES[1]),
			0xe3 => harness.force_close(1, harness.chan_a_id(), 0, FORCE_CLOSE_ERROR_MESSAGES[2]),
			0xe4 => harness.force_close(2, harness.chan_b_id(), 1, FORCE_CLOSE_ERROR_MESSAGES[3]),

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
