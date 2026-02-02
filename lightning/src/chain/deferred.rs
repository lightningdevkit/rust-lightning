// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A wrapper around [`ChainMonitor`] that defers `Watch` operations for later flushing.
//!
//! This module provides [`DeferredChainMonitor`], which queues [`chain::Watch::watch_channel`]
//! and [`chain::Watch::update_channel`] calls instead of immediately executing them. The queued
//! operations are executed when [`DeferredChainMonitor::flush`] is called.
//!
//! This enables a safe persistence pattern where the [`ChannelManager`] is persisted before
//! the channel monitors, ensuring crash safety:
//!
//! 1. Capture the pending operation count with [`DeferredChainMonitor::pending_operation_count`]
//! 2. Persist the [`ChannelManager`]
//! 3. Flush the captured operations with [`DeferredChainMonitor::flush`]
//!
//! [`ChainMonitor`]: super::chainmonitor::ChainMonitor
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{AChainMonitor, ChainMonitor, Persist};
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, MonitorEvent};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::{BestBlock, ChannelMonitorUpdateStatus, Watch};
use crate::events::{EventHandler, EventsProvider};
use crate::ln::msgs::{BaseMessageHandler, Init, MessageSendEvent, SendOnlyMessageHandler};
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::EntropySource;
use crate::sync::Mutex;
use crate::types::features::{InitFeatures, NodeFeatures};
use crate::util::errors::APIError;
use crate::util::logger::Logger;

use bitcoin::block::Header;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;

/// The set of monitor operations that [`DeferredChainMonitor::flush_with_target`] delegates to.
///
/// [`ChainMonitor`] implements this trait by forwarding to its [`Watch`] and
/// [`channel_monitor_updated`] methods. In tests, a mock can implement this trait
/// to verify flush behavior (call ordering, status handling) without needing a real
/// [`ChainMonitor`] or any channel setup.
///
/// [`channel_monitor_updated`]: ChainMonitor::channel_monitor_updated
pub(crate) trait MonitorFlushTarget<ChannelSigner: EcdsaChannelSigner> {
	/// Persists and begins watching a new channel monitor.
	/// Mirrors [`Watch::watch_channel`].
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()>;

	/// Applies an update to an existing channel monitor.
	/// Mirrors [`Watch::update_channel`].
	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus;

	/// Signals that an asynchronous monitor update has completed.
	/// Mirrors [`ChainMonitor::channel_monitor_updated`].
	fn channel_monitor_updated(
		&self, channel_id: ChannelId, completed_update_id: u64,
	) -> Result<(), APIError>;
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> MonitorFlushTarget<ChannelSigner> for ChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()> {
		Watch::watch_channel(self, channel_id, monitor)
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus {
		Watch::update_channel(self, channel_id, update)
	}

	fn channel_monitor_updated(
		&self, channel_id: ChannelId, completed_update_id: u64,
	) -> Result<(), APIError> {
		ChainMonitor::channel_monitor_updated(self, channel_id, completed_update_id)
	}
}

/// A pending operation queued for later execution in [`DeferredChainMonitor::flush`].
enum PendingMonitorOp<ChannelSigner: EcdsaChannelSigner> {
	/// A new monitor to insert and persist.
	NewMonitor { channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>, update_id: u64 },
	/// An update to apply and persist.
	Update { channel_id: ChannelId, update: ChannelMonitorUpdate },
}

/// A wrapper around [`ChainMonitor`] that defers `Watch` operations for later flushing.
///
/// When used with the background processor, this enables safe persistence ordering:
/// the [`ChannelManager`] is persisted before the channel monitors are updated.
///
/// # Usage
///
/// ```ignore
/// // Create the wrapper around ChainMonitor
/// let deferred = DeferredChainMonitor::new(...);
///
/// // In the persistence loop:
/// let pending_count = deferred.pending_operation_count();
/// // ... persist ChannelManager ...
/// deferred.flush(pending_count, &logger);
/// ```
///
/// [`ChainMonitor`]: super::chainmonitor::ChainMonitor
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub struct DeferredChainMonitor<
	ChannelSigner: EcdsaChannelSigner,
	C: chain::Filter,
	T: BroadcasterInterface,
	F: FeeEstimator,
	L: Logger,
	P: Deref,
	ES: EntropySource,
> where
	P::Target: Persist<ChannelSigner>,
{
	chain_monitor: ChainMonitor<ChannelSigner, C, T, F, L, P, ES>,
	pending_ops: Mutex<Vec<PendingMonitorOp<ChannelSigner>>>,
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	/// Creates a new `DeferredChainMonitor` by instantiating the inner [`ChainMonitor`]
	/// with the provided components.
	///
	/// Operations are deferred and must be flushed with [`Self::flush`].
	pub fn new(
		chain_source: Option<C>, broadcaster: T, logger: L, fee_estimator: F, persister: P,
		entropy_source: ES, peer_storage_key: crate::sign::PeerStorageKey,
	) -> Self {
		let chain_monitor = ChainMonitor::new(
			chain_source,
			broadcaster,
			logger,
			fee_estimator,
			persister,
			entropy_source,
			peer_storage_key,
		);
		Self { chain_monitor, pending_ops: Mutex::new(Vec::new()) }
	}

	/// Returns a reference to the inner [`ChainMonitor`].
	pub fn inner(&self) -> &ChainMonitor<ChannelSigner, C, T, F, L, P, ES> {
		&self.chain_monitor
	}

	/// Processes up to `count` pending operations, forwarding each to `target`.
	///
	/// For both [`NewMonitor`] and [`Update`] variants, the operation is forwarded to the
	/// corresponding [`MonitorFlushTarget`] method. If the result is [`Completed`],
	/// [`MonitorFlushTarget::channel_monitor_updated`] is called immediately so the
	/// [`ChannelManager`] can release any held messages. [`InProgress`] is a no-op (async
	/// persistence will signal later). [`UnrecoverableError`] panics.
	///
	/// For [`NewMonitor`], an `Err(())` from `watch_channel` (e.g. duplicate channel) is
	/// logged — the monitor has already been consumed so it cannot be retried.
	///
	/// Returns early if the queue empties before `count` operations have been processed.
	///
	/// [`NewMonitor`]: PendingMonitorOp::NewMonitor
	/// [`Update`]: PendingMonitorOp::Update
	/// [`Completed`]: ChannelMonitorUpdateStatus::Completed
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	/// [`UnrecoverableError`]: ChannelMonitorUpdateStatus::UnrecoverableError
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	pub(crate) fn flush_with_target<M: MonitorFlushTarget<ChannelSigner>>(
		&self, count: usize, target: &M, logger: &L,
	) {
		for _ in 0..count {
			let op = {
				let mut queue = self.pending_ops.lock().unwrap();
				if queue.is_empty() {
					return;
				}
				queue.remove(0)
			};

			let (channel_id, update_id, status) = match op {
				PendingMonitorOp::NewMonitor { channel_id, monitor, update_id } => {
					match target.watch_channel(channel_id, monitor) {
						Ok(status) => (channel_id, update_id, status),
						Err(()) => {
							log_error!(logger, "watch_channel failed for channel {}", channel_id);
							continue;
						},
					}
				},
				PendingMonitorOp::Update { channel_id, update } => {
					let update_id = update.update_id;
					let status = target.update_channel(channel_id, &update);
					(channel_id, update_id, status)
				},
			};

			match status {
				ChannelMonitorUpdateStatus::Completed => {
					if let Err(e) = target.channel_monitor_updated(channel_id, update_id) {
						log_error!(
							logger,
							"channel_monitor_updated failed for channel {}: {:?}",
							channel_id,
							e
						);
					}
				},
				ChannelMonitorUpdateStatus::InProgress => {},
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					panic!("UnrecoverableError during monitor operation");
				},
			}
		}
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> AChainMonitor for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	type Signer = ChannelSigner;
	type Filter = C;
	type Broadcaster = T;
	type FeeEstimator = F;
	type Logger = L;
	type Persister = P;
	type PersisterTarget = P::Target;
	type EntropySource = ES;

	fn get_cm(&self) -> &ChainMonitor<ChannelSigner, C, T, F, L, P, ES> {
		&self.chain_monitor
	}

	fn pending_operation_count(&self) -> usize {
		self.pending_ops.lock().unwrap().len()
	}

	fn flush(&self, count: usize, logger: &L) {
		self.flush_with_target(count, &self.chain_monitor, logger);
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> chain::Watch<ChannelSigner> for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()> {
		let update_id = monitor.get_latest_update_id();
		let mut pending_ops = self.pending_ops.lock().unwrap();

		// Check if this channel_id is already pending (would be a duplicate)
		let already_pending = pending_ops.iter().any(|op| match op {
			PendingMonitorOp::NewMonitor { channel_id: id, .. } => *id == channel_id,
			_ => false,
		});
		if already_pending {
			return Err(());
		}

		pending_ops.push(PendingMonitorOp::NewMonitor { channel_id, monitor, update_id });
		Ok(ChannelMonitorUpdateStatus::InProgress)
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus {
		let mut pending_ops = self.pending_ops.lock().unwrap();
		pending_ops.push(PendingMonitorOp::Update { channel_id, update: update.clone() });
		ChannelMonitorUpdateStatus::InProgress
	}

	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)> {
		self.chain_monitor.release_pending_monitor_events()
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> BaseMessageHandler for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		self.chain_monitor.get_and_clear_pending_msg_events()
	}

	fn peer_disconnected(&self, their_node_id: PublicKey) {
		self.chain_monitor.peer_disconnected(their_node_id)
	}

	fn provided_node_features(&self) -> NodeFeatures {
		self.chain_monitor.provided_node_features()
	}

	fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
		self.chain_monitor.provided_init_features(their_node_id)
	}

	fn peer_connected(
		&self, their_node_id: PublicKey, msg: &Init, inbound: bool,
	) -> Result<(), ()> {
		self.chain_monitor.peer_connected(their_node_id, msg, inbound)
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> SendOnlyMessageHandler for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> chain::Listen for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		self.chain_monitor.filtered_block_connected(header, txdata, height)
	}

	fn blocks_disconnected(&self, fork_point: BestBlock) {
		self.chain_monitor.blocks_disconnected(fork_point)
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> chain::Confirm for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		self.chain_monitor.transactions_confirmed(header, txdata, height)
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		self.chain_monitor.transaction_unconfirmed(txid)
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		self.chain_monitor.best_block_updated(header, height)
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		self.chain_monitor.get_relevant_txids()
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: chain::Filter,
		T: BroadcasterInterface,
		F: FeeEstimator,
		L: Logger,
		P: Deref,
		ES: EntropySource,
	> EventsProvider for DeferredChainMonitor<ChannelSigner, C, T, F, L, P, ES>
where
	P::Target: Persist<ChannelSigner>,
{
	fn process_pending_events<H: Deref>(&self, handler: H)
	where
		H::Target: EventHandler,
	{
		self.chain_monitor.process_pending_events(handler)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
	use crate::chain::transaction::OutPoint;
	use crate::chain::ChannelMonitorUpdateStatus;
	use crate::chain::Confirm;
	use crate::ln::chan_utils::{
		ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
		HolderCommitmentTransaction,
	};
	use crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};
	use crate::ln::channelmanager::{ChainParameters, ChannelManager, PaymentId};
	use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, Init, MessageSendEvent};
	use crate::ln::outbound_payment::RecipientOnionFields;
	use crate::ln::script::ShutdownScript;
	use crate::sign::{ChannelSigner, InMemorySigner, NodeSigner};
	use crate::sync::RwLock;
	use crate::types::features::ChannelTypeFeatures;
	use crate::util::config::UserConfig;
	use crate::util::dyn_signer::DynSigner;
	use crate::util::test_channel_signer::TestChannelSigner;
	use crate::util::test_utils::{
		TestBroadcaster, TestChainSource, TestFeeEstimator, TestKeysInterface, TestLogger,
		TestMessageRouter, TestPersister, TestRouter, TestScorer,
	};
	use alloc::sync::Arc;
	use bitcoin::hashes::Hash;
	use bitcoin::script::ScriptBuf;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::Network;

	/// Concrete `DeferredChainMonitor` type wired to the standard test utilities.
	type TestDeferredChainMonitor<'a> = DeferredChainMonitor<
		TestChannelSigner,
		&'a TestChainSource,
		&'a TestBroadcaster,
		&'a TestFeeEstimator,
		&'a TestLogger,
		&'a TestPersister,
		&'a TestKeysInterface,
	>;

	/// Creates a minimal `ChannelMonitorUpdate` with no actual update steps.
	fn dummy_update(update_id: u64, channel_id: ChannelId) -> ChannelMonitorUpdate {
		ChannelMonitorUpdate { updates: vec![], update_id, channel_id: Some(channel_id) }
	}

	/// Creates a minimal `ChannelMonitor<TestChannelSigner>` for the given `channel_id`.
	fn dummy_monitor(channel_id: ChannelId) -> ChannelMonitor<TestChannelSigner> {
		let secp_ctx = Secp256k1::new();
		let dummy_key =
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let keys = InMemorySigner::new(
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			true,
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			[41; 32],
			[0; 32],
			[0; 32],
		);
		let counterparty_pubkeys = crate::ln::chan_utils::ChannelPublicKeys {
			funding_pubkey: dummy_key,
			revocation_basepoint: RevocationBasepoint::from(dummy_key),
			payment_point: dummy_key,
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(dummy_key),
			htlc_basepoint: HtlcBasepoint::from(dummy_key),
		};
		let funding_outpoint = OutPoint { txid: Txid::all_zeros(), index: u16::MAX };
		let channel_parameters = ChannelTransactionParameters {
			holder_pubkeys: keys.pubkeys(&secp_ctx),
			holder_selected_contest_delay: 66,
			is_outbound_from_holder: true,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
				pubkeys: counterparty_pubkeys,
				selected_contest_delay: 67,
			}),
			funding_outpoint: Some(funding_outpoint),
			splice_parent_funding_txid: None,
			channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
			channel_value_satoshis: 0,
		};
		let shutdown_script = ShutdownScript::new_p2wpkh_from_pubkey(dummy_key);
		let best_block = BestBlock::from_network(Network::Testnet);
		let signer = TestChannelSigner::new(DynSigner::new(keys));
		ChannelMonitor::new(
			secp_ctx,
			signer,
			Some(shutdown_script.into_inner()),
			0,
			&ScriptBuf::new(),
			&channel_parameters,
			true,
			0,
			HolderCommitmentTransaction::dummy(0, funding_outpoint, Vec::new()),
			best_block,
			dummy_key,
			channel_id,
			false,
		)
	}

	/// Records the sequence of calls that `flush_with_target` makes on the mock target.
	#[derive(Debug, PartialEq)]
	enum FlushCall {
		WatchChannel { channel_id: ChannelId },
		UpdateChannel { channel_id: ChannelId, update_id: u64 },
		MonitorUpdated { channel_id: ChannelId, update_id: u64 },
	}

	/// A mock [`MonitorFlushTarget`] that records every call and returns pre-configured
	/// statuses. Each `watch_channel` / `update_channel` call pops the next status from
	/// the corresponding result queue.
	struct MockFlushTarget {
		watch_results: Mutex<Vec<Result<ChannelMonitorUpdateStatus, ()>>>,
		update_results: Mutex<Vec<ChannelMonitorUpdateStatus>>,
		calls: Mutex<Vec<FlushCall>>,
	}

	impl MockFlushTarget {
		fn new(
			watch_results: Vec<Result<ChannelMonitorUpdateStatus, ()>>,
			update_results: Vec<ChannelMonitorUpdateStatus>,
		) -> Self {
			Self {
				watch_results: Mutex::new(watch_results),
				update_results: Mutex::new(update_results),
				calls: Mutex::new(Vec::new()),
			}
		}

		fn take_calls(&self) -> Vec<FlushCall> {
			core::mem::take(&mut *self.calls.lock().unwrap())
		}
	}

	impl MonitorFlushTarget<TestChannelSigner> for MockFlushTarget {
		fn watch_channel(
			&self, channel_id: ChannelId, _monitor: ChannelMonitor<TestChannelSigner>,
		) -> Result<ChannelMonitorUpdateStatus, ()> {
			self.calls.lock().unwrap().push(FlushCall::WatchChannel { channel_id });
			self.watch_results.lock().unwrap().remove(0)
		}

		fn update_channel(
			&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
		) -> ChannelMonitorUpdateStatus {
			self.calls
				.lock()
				.unwrap()
				.push(FlushCall::UpdateChannel { channel_id, update_id: update.update_id });
			self.update_results.lock().unwrap().remove(0)
		}

		fn channel_monitor_updated(
			&self, channel_id: ChannelId, completed_update_id: u64,
		) -> Result<(), APIError> {
			self.calls
				.lock()
				.unwrap()
				.push(FlushCall::MonitorUpdated { channel_id, update_id: completed_update_id });
			Ok(())
		}
	}

	/// Tests queueing and flushing of both `watch_channel` and `update_channel` operations:
	/// - Both return `InProgress` and increment `pending_operation_count`.
	/// - `flush_with_target` drains at most `count` operations from the queue.
	/// - `Completed` status triggers `channel_monitor_updated`; `InProgress` does not.
	/// - Flushing an empty queue is a no-op.
	#[test]
	fn test_queue_and_flush() {
		let broadcaster = TestBroadcaster::new(Network::Testnet);
		let fee_est = TestFeeEstimator::new(253);
		let logger = TestLogger::new();
		let persister = TestPersister::new();
		let chain_source = TestChainSource::new(Network::Testnet);
		let keys = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let deferred = DeferredChainMonitor::new(
			Some(&chain_source),
			&broadcaster,
			&logger,
			&fee_est,
			&persister,
			&keys,
			keys.get_peer_storage_key(),
		);

		// Queue starts empty.
		assert_eq!(deferred.pending_operation_count(), 0);

		// Queue a watch_channel, verifying InProgress status.
		let chan = ChannelId::from_bytes([1u8; 32]);
		let status = deferred.watch_channel(chan, dummy_monitor(chan));
		assert_eq!(status, Ok(ChannelMonitorUpdateStatus::InProgress));
		assert_eq!(deferred.pending_operation_count(), 1);

		// Queue two updates after the watch.
		assert_eq!(
			deferred.update_channel(chan, &dummy_update(2, chan)),
			ChannelMonitorUpdateStatus::InProgress
		);
		assert_eq!(
			deferred.update_channel(chan, &dummy_update(3, chan)),
			ChannelMonitorUpdateStatus::InProgress
		);
		assert_eq!(deferred.pending_operation_count(), 3);

		// Flush 2 of 3: watch Completed (triggers monitor_updated), update InProgress (does not).
		let mock = MockFlushTarget::new(
			vec![Ok(ChannelMonitorUpdateStatus::Completed)],
			vec![ChannelMonitorUpdateStatus::InProgress],
		);
		deferred.flush_with_target(2, &mock, &&logger);

		assert_eq!(deferred.pending_operation_count(), 1);
		assert_eq!(
			mock.take_calls(),
			vec![
				FlushCall::WatchChannel { channel_id: chan },
				FlushCall::MonitorUpdated { channel_id: chan, update_id: 0 },
				FlushCall::UpdateChannel { channel_id: chan, update_id: 2 },
			]
		);

		// Flush remaining: Completed triggers monitor_updated.
		let mock = MockFlushTarget::new(vec![], vec![ChannelMonitorUpdateStatus::Completed]);
		deferred.flush_with_target(1, &mock, &&logger);
		assert_eq!(deferred.pending_operation_count(), 0);
		assert_eq!(
			mock.take_calls(),
			vec![
				FlushCall::UpdateChannel { channel_id: chan, update_id: 3 },
				FlushCall::MonitorUpdated { channel_id: chan, update_id: 3 },
			]
		);

		// Flushing an empty queue is a no-op.
		let mock = MockFlushTarget::new(vec![], vec![]);
		deferred.flush_with_target(5, &mock, &&logger);
		assert!(mock.take_calls().is_empty());
	}

	// ==================== Integration tests ====================
	//
	// These tests exercise the full `DeferredChainMonitor` with real `ChannelManager`s and a
	// complete channel open + payment flow.

	/// Test node infrastructure components.
	struct TestNodeComponents {
		broadcaster: TestBroadcaster,
		fee_estimator: TestFeeEstimator,
		logger: TestLogger,
		persister: TestPersister,
		chain_source: TestChainSource,
		keys_manager: TestKeysInterface,
		scorer: RwLock<TestScorer>,
	}

	impl TestNodeComponents {
		fn new(seed: u8, id: &str) -> Self {
			Self {
				broadcaster: TestBroadcaster::new(Network::Testnet),
				fee_estimator: TestFeeEstimator::new(253),
				logger: TestLogger::with_id(id.to_string()),
				persister: TestPersister::new(),
				chain_source: TestChainSource::new(Network::Testnet),
				keys_manager: TestKeysInterface::new(&[seed; 32], Network::Testnet),
				scorer: RwLock::new(TestScorer::new()),
			}
		}

		fn create_deferred_chain_monitor(&self) -> TestDeferredChainMonitor<'_> {
			DeferredChainMonitor::new(
				Some(&self.chain_source),
				&self.broadcaster,
				&self.logger,
				&self.fee_estimator,
				&self.persister,
				&self.keys_manager,
				self.keys_manager.get_peer_storage_key(),
			)
		}

		fn create_router<'a>(
			&'a self, network_graph: &Arc<crate::routing::gossip::NetworkGraph<&'a TestLogger>>,
		) -> TestRouter<'a> {
			TestRouter::new(Arc::clone(network_graph), &self.logger, &self.scorer)
		}

		fn create_message_router<'a>(
			&'a self, network_graph: &Arc<crate::routing::gossip::NetworkGraph<&'a TestLogger>>,
		) -> TestMessageRouter<'a> {
			TestMessageRouter::new_default(Arc::clone(network_graph), &self.keys_manager)
		}
	}

	type TestChannelManager<'a> = ChannelManager<
		&'a TestDeferredChainMonitor<'a>,
		&'a TestBroadcaster,
		&'a TestKeysInterface,
		&'a TestKeysInterface,
		&'a TestKeysInterface,
		&'a TestFeeEstimator,
		&'a TestRouter<'a>,
		&'a TestMessageRouter<'a>,
		&'a TestLogger,
	>;

	/// Exchanges messages between two channel managers until no more messages are pending.
	/// Returns true if any HTLC was forwarded (update_add_htlc received).
	fn exchange_messages<'a>(
		cm0: &TestChannelManager<'a>, cm1: &TestChannelManager<'a>,
		deferred_0: &TestDeferredChainMonitor<'a>, deferred_1: &TestDeferredChainMonitor<'a>,
		node_0_id: PublicKey, node_1_id: PublicKey, process_htlc_forwards: bool,
		logger_0: &'a TestLogger, logger_1: &'a TestLogger,
	) -> bool {
		let mut htlc_forwarded = false;

		for _ in 0..10 {
			deferred_0.flush(deferred_0.pending_operation_count(), &logger_0);
			deferred_1.flush(deferred_1.pending_operation_count(), &logger_1);

			let events_0 = cm0.get_and_clear_pending_msg_events();
			let events_1 = cm1.get_and_clear_pending_msg_events();

			if events_0.is_empty() && events_1.is_empty() {
				break;
			}

			// Forward messages from node 0 to node 1
			for event in events_0 {
				match event {
					MessageSendEvent::UpdateHTLCs { updates, .. } => {
						for update in &updates.update_add_htlcs {
							cm1.handle_update_add_htlc(node_0_id, update);
							htlc_forwarded = true;
						}
						for update in updates.update_fulfill_htlcs {
							cm1.handle_update_fulfill_htlc(node_0_id, update);
						}
						for cs in &updates.commitment_signed {
							cm1.handle_commitment_signed(node_0_id, cs);
						}
					},
					MessageSendEvent::SendRevokeAndACK { msg, .. } => {
						cm1.handle_revoke_and_ack(node_0_id, &msg);
					},
					_ => {},
				}
			}

			// Forward messages from node 1 to node 0
			for event in events_1 {
				match event {
					MessageSendEvent::UpdateHTLCs { updates, .. } => {
						for update in &updates.update_add_htlcs {
							cm0.handle_update_add_htlc(node_1_id, update);
							htlc_forwarded = true;
						}
						for update in updates.update_fulfill_htlcs {
							cm0.handle_update_fulfill_htlc(node_1_id, update);
						}
						for cs in &updates.commitment_signed {
							cm0.handle_commitment_signed(node_1_id, cs);
						}
					},
					MessageSendEvent::SendRevokeAndACK { msg, .. } => {
						cm0.handle_revoke_and_ack(node_1_id, &msg);
					},
					_ => {},
				}
			}

			deferred_0.flush(deferred_0.pending_operation_count(), &logger_0);
			deferred_1.flush(deferred_1.pending_operation_count(), &logger_1);

			if process_htlc_forwards {
				cm1.process_pending_htlc_forwards();
			}
		}

		htlc_forwarded
	}

	/// Tests that `DeferredChainMonitor` properly defers `watch_channel` and
	/// `update_channel` operations until `flush()` is called, using real
	/// ChannelManagers and a complete channel open + payment flow.
	#[test]
	fn test_deferred_monitor_payment() {
		// Set up node infrastructure
		let components_0 = TestNodeComponents::new(0, "node0");
		let components_1 = TestNodeComponents::new(1, "node1");

		let network = Network::Testnet;
		let params =
			ChainParameters { network, best_block: crate::chain::BestBlock::from_network(network) };
		let genesis_block = bitcoin::constants::genesis_block(network);

		// Create deferred chain monitors
		let deferred_0 = components_0.create_deferred_chain_monitor();
		let deferred_1 = components_1.create_deferred_chain_monitor();

		// Create routers and message routers
		let network_graph_0 =
			Arc::new(crate::routing::gossip::NetworkGraph::new(network, &components_0.logger));
		let network_graph_1 =
			Arc::new(crate::routing::gossip::NetworkGraph::new(network, &components_1.logger));
		let router_0 = components_0.create_router(&network_graph_0);
		let router_1 = components_1.create_router(&network_graph_1);
		let message_router_0 = components_0.create_message_router(&network_graph_0);
		let message_router_1 = components_1.create_message_router(&network_graph_1);

		// Create channel config
		let mut config = UserConfig::default();
		config.channel_handshake_config.announce_for_forwarding = false;
		config.channel_handshake_config.minimum_depth = 1;

		// Create channel managers
		let channel_manager_0 = ChannelManager::new(
			&components_0.fee_estimator,
			&deferred_0,
			&components_0.broadcaster,
			&router_0,
			&message_router_0,
			&components_0.logger,
			&components_0.keys_manager,
			&components_0.keys_manager,
			&components_0.keys_manager,
			config.clone(),
			params.clone(),
			genesis_block.header.time,
		);

		let channel_manager_1 = ChannelManager::new(
			&components_1.fee_estimator,
			&deferred_1,
			&components_1.broadcaster,
			&router_1,
			&message_router_1,
			&components_1.logger,
			&components_1.keys_manager,
			&components_1.keys_manager,
			&components_1.keys_manager,
			config,
			params,
			genesis_block.header.time,
		);

		// ===== Connect peers =====
		let node_0_id = channel_manager_0.get_our_node_id();
		let node_1_id = channel_manager_1.get_our_node_id();

		let init_0 = Init {
			features: channel_manager_0.init_features(),
			networks: None,
			remote_network_address: None,
		};
		let init_1 = Init {
			features: channel_manager_1.init_features(),
			networks: None,
			remote_network_address: None,
		};

		channel_manager_0.peer_connected(node_1_id, &init_1, true).unwrap();
		channel_manager_1.peer_connected(node_0_id, &init_0, false).unwrap();

		// ===== Open channel =====
		// Initial state: no pending operations
		assert_eq!(deferred_0.pending_operation_count(), 0);

		channel_manager_0.create_channel(node_1_id, 100_000, 10_000, 42, None, None).unwrap();

		// Get open_channel and handle it
		let events = channel_manager_0.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let open_channel = match &events[0] {
			crate::ln::msgs::MessageSendEvent::SendOpenChannel { msg, .. } => msg.clone(),
			_ => panic!("Expected SendOpenChannel"),
		};
		channel_manager_1.handle_open_channel(node_0_id, &open_channel);

		// Get accept_channel and handle it
		let events = channel_manager_1.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let accept_channel = match &events[0] {
			crate::ln::msgs::MessageSendEvent::SendAcceptChannel { msg, .. } => msg.clone(),
			_ => panic!("Expected SendAcceptChannel"),
		};
		channel_manager_0.handle_accept_channel(node_1_id, &accept_channel);

		// Get FundingGenerationReady and create funding tx
		let events = channel_manager_0.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let (temp_chan_id, funding_tx) = match &events[0] {
			crate::events::Event::FundingGenerationReady {
				temporary_channel_id,
				output_script,
				channel_value_satoshis,
				..
			} => {
				use bitcoin::transaction::{Transaction, TxOut};
				let tx = Transaction {
					version: bitcoin::transaction::Version::TWO,
					lock_time: bitcoin::absolute::LockTime::ZERO,
					input: Vec::new(),
					output: vec![TxOut {
						value: bitcoin::Amount::from_sat(*channel_value_satoshis),
						script_pubkey: output_script.clone(),
					}],
				};
				(*temporary_channel_id, tx)
			},
			_ => panic!("Expected FundingGenerationReady"),
		};

		// Clone the funding tx for later confirmation
		let funding_tx_clone = funding_tx.clone();

		// Fund the channel - this sends funding_created to node 1
		channel_manager_0
			.funding_transaction_generated(temp_chan_id, node_1_id, funding_tx)
			.unwrap();

		// Get funding_created message and send to node 1
		let events = channel_manager_0.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let funding_created = match &events[0] {
			crate::ln::msgs::MessageSendEvent::SendFundingCreated { msg, .. } => msg.clone(),
			_ => panic!("Expected SendFundingCreated"),
		};

		// Node 1 handles funding_created, which triggers watch_channel on deferred_1
		// and sends funding_signed back
		channel_manager_1.handle_funding_created(node_0_id, &funding_created);

		// Flush node 1's deferred watch_channel operation
		assert_eq!(
			deferred_1.pending_operation_count(),
			1,
			"node 1 watch_channel should be queued"
		);
		deferred_1.flush(1, &&components_1.logger);
		assert_eq!(deferred_1.pending_operation_count(), 0);

		// Get funding_signed and send to node 0
		let events = channel_manager_1.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let funding_signed = match &events[0] {
			crate::ln::msgs::MessageSendEvent::SendFundingSigned { msg, .. } => msg.clone(),
			_ => panic!("Expected SendFundingSigned"),
		};

		// Node 0 handles funding_signed - THIS triggers watch_channel on deferred_0
		channel_manager_0.handle_funding_signed(node_1_id, &funding_signed);

		// ===== Verify deferred behavior for watch_channel =====
		// watch_channel should be queued (not yet applied to inner monitor)
		assert_eq!(deferred_0.pending_operation_count(), 1, "watch_channel should be queued");

		// Inner ChainMonitor should NOT have the monitor yet
		assert!(
			deferred_0.inner().list_monitors().is_empty(),
			"Monitor should not be in inner ChainMonitor before flush"
		);

		// Flush the watch_channel operation
		deferred_0.flush(1, &&components_0.logger);

		// Now the monitor should be present
		assert_eq!(deferred_0.pending_operation_count(), 0);
		assert_eq!(
			deferred_0.inner().list_monitors().len(),
			1,
			"Monitor should be in inner ChainMonitor after flush"
		);

		// Drain pending messages so the channel handshake can proceed.
		let _ = channel_manager_0.get_and_clear_pending_msg_events();

		// ===== Simulate funding confirmation and exchange channel_ready =====
		use bitcoin::block::{Header, Version};
		use bitcoin::hash_types::TxMerkleNode;
		use bitcoin::hashes::Hash;
		use bitcoin::CompactTarget;

		let header = Header {
			version: Version::from_consensus(1),
			prev_blockhash: genesis_block.block_hash(),
			merkle_root: TxMerkleNode::all_zeros(),
			time: 42,
			bits: CompactTarget::from_consensus(0x207fffff),
			nonce: 0,
		};

		// Confirm the funding transaction in a block
		let txdata: &[(usize, &bitcoin::Transaction)] = &[(0usize, &funding_tx_clone)];
		channel_manager_0.transactions_confirmed(&header, txdata, 1);
		channel_manager_1.transactions_confirmed(&header, txdata, 1);
		channel_manager_0.best_block_updated(&header, 1);
		channel_manager_1.best_block_updated(&header, 1);

		// Also notify the chain monitors
		deferred_0.inner().transactions_confirmed(&header, txdata, 1);
		deferred_1.inner().transactions_confirmed(&header, txdata, 1);

		// Exchange channel_ready messages - may take multiple rounds
		for _ in 0..3 {
			let events_0 = channel_manager_0.get_and_clear_pending_msg_events();
			let events_1 = channel_manager_1.get_and_clear_pending_msg_events();

			for event in &events_0 {
				if let crate::ln::msgs::MessageSendEvent::SendChannelReady { msg, .. } = event {
					channel_manager_1.handle_channel_ready(node_0_id, msg);
				}
			}
			for event in &events_1 {
				if let crate::ln::msgs::MessageSendEvent::SendChannelReady { msg, .. } = event {
					channel_manager_0.handle_channel_ready(node_1_id, msg);
				}
			}

			// Check if channel is usable yet
			if !channel_manager_0.list_usable_channels().is_empty() {
				break;
			}
		}

		// ===== Send a payment from node 0 to node 1 =====
		// Build a route manually since the network graph is empty
		use crate::routing::router::{Path, Route, RouteHop};
		use crate::types::features::ChannelFeatures;

		// Create an inbound payment on node 1 to get payment hash and secret
		let amt_msat = 10_000_u64;
		let (payment_hash, payment_secret) =
			channel_manager_1.create_inbound_payment(Some(amt_msat), 3600, None).unwrap();
		let payment_id = PaymentId([1u8; 32]);

		// Get the usable channel and its SCID
		let usable_channels = channel_manager_0.list_usable_channels();
		assert_eq!(usable_channels.len(), 1, "Should have one usable channel");
		let scid = usable_channels[0].short_channel_id.expect("Channel should have SCID");

		// Build a direct route to node 1
		let route = Route {
			paths: vec![Path {
				hops: vec![RouteHop {
					pubkey: node_1_id,
					node_features: channel_manager_1.node_features(),
					short_channel_id: scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: amt_msat,
					cltv_expiry_delta: 40,
					maybe_announced_channel: false,
				}],
				blinded_tail: None,
			}],
			route_params: None,
		};

		// Send payment using the pre-built route with the payment secret
		channel_manager_0
			.send_payment_with_route(
				route,
				payment_hash,
				RecipientOnionFields::secret_only(payment_secret),
				payment_id,
			)
			.unwrap();

		// ===== Verify deferred behavior for update_channel =====
		// update_channel should be queued (commitment transaction update)
		let pending_count = deferred_0.pending_operation_count();
		assert!(pending_count >= 1, "update_channel should be queued, got {}", pending_count);

		// Flush the pending updates so node 0's monitor is up to date
		deferred_0.flush(pending_count, &&components_0.logger);
		assert_eq!(deferred_0.pending_operation_count(), 0, "All operations should be flushed");

		// Exchange messages to complete the commitment dance and HTLC forwarding
		let htlc_forwarded = exchange_messages(
			&channel_manager_0,
			&channel_manager_1,
			&deferred_0,
			&deferred_1,
			node_0_id,
			node_1_id,
			true, // process HTLC forwards on node 1
			&&components_0.logger,
			&&components_1.logger,
		);
		assert!(htlc_forwarded, "HTLC should have been forwarded to node 1");

		// Final flush and process to ensure all pending HTLCs are handled
		deferred_0.flush(deferred_0.pending_operation_count(), &&components_0.logger);
		deferred_1.flush(deferred_1.pending_operation_count(), &&components_1.logger);
		channel_manager_1.process_pending_htlc_forwards();

		// Node 1 should now have a pending HTLC to claim
		// Check for PaymentClaimable event
		let events_1 = channel_manager_1.get_and_clear_pending_events();
		let mut payment_claimable = false;
		for event in &events_1 {
			if let crate::events::Event::PaymentClaimable { payment_hash: hash, purpose, .. } =
				event
			{
				assert_eq!(*hash, payment_hash);
				payment_claimable = true;
				// Get the preimage from the payment purpose and claim
				if let crate::events::PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: Some(preimage),
					..
				} = purpose
				{
					channel_manager_1.claim_funds(*preimage);
				} else {
					panic!("Expected Bolt11InvoicePayment with preimage");
				}
			}
		}
		assert!(payment_claimable, "Node 1 should have received PaymentClaimable event");

		// Exchange messages to complete the payment claim
		exchange_messages(
			&channel_manager_0,
			&channel_manager_1,
			&deferred_0,
			&deferred_1,
			node_0_id,
			node_1_id,
			false, // no HTLC forwards needed for claim phase
			&&components_0.logger,
			&&components_1.logger,
		);

		// Verify payment completed on node 0
		let events_0 = channel_manager_0.get_and_clear_pending_events();
		let mut payment_sent = false;
		for event in &events_0 {
			if let crate::events::Event::PaymentSent { payment_hash: hash, .. } = event {
				assert_eq!(*hash, payment_hash);
				payment_sent = true;
			}
		}
		assert!(payment_sent, "Node 0 should have received PaymentSent event");

		// Verify payment claimed on node 1
		let events_1 = channel_manager_1.get_and_clear_pending_events();
		let mut payment_claimed = false;
		for event in &events_1 {
			if let crate::events::Event::PaymentClaimed { payment_hash: hash, .. } = event {
				assert_eq!(*hash, payment_hash);
				payment_claimed = true;
			}
		}
		assert!(payment_claimed, "Node 1 should have received PaymentClaimed event");

		// Both monitors should still be present and updated
		assert_eq!(
			deferred_0.inner().list_monitors().len(),
			1,
			"Node 0 monitor should still be present after payment completion"
		);
		assert_eq!(
			deferred_1.inner().list_monitors().len(),
			1,
			"Node 1 monitor should still be present after payment completion"
		);
	}
}
