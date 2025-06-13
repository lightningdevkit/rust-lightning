// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains an [`OutputSweeper`] utility that keeps track of
//! [`SpendableOutputDescriptor`]s, i.e., persists them in a given [`KVStore`] and regularly retries
//! sweeping them.

use crate::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, ARCHIVAL_DELAY_BLOCKS};
use crate::chain::{self, BestBlock, Confirm, Filter, Listen, WatchedOutput};
use crate::io;
use crate::ln::msgs::DecodeError;
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::sign::{
	ChangeDestinationSource, ChangeDestinationSourceSync, ChangeDestinationSourceSyncWrapper,
	OutputSpender, SpendableOutputDescriptor,
};
use crate::sync::Arc;
use crate::sync::Mutex;
use crate::util::logger::Logger;
use crate::util::persist::{
	KVStore, OUTPUT_SWEEPER_PERSISTENCE_KEY, OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
	OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::util::ser::{Readable, ReadableArgs, Writeable};
use crate::{impl_writeable_tlv_based, log_debug, log_error};

use bitcoin::block::Header;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};

use core::future::Future;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task;

use super::async_poll::dummy_waker;

/// The number of blocks we wait before we prune the tracked spendable outputs.
pub const PRUNE_DELAY_BLOCKS: u32 = ARCHIVAL_DELAY_BLOCKS + ANTI_REORG_DELAY;

/// The state of a spendable output currently tracked by an [`OutputSweeper`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedSpendableOutput {
	/// The tracked output descriptor.
	pub descriptor: SpendableOutputDescriptor,
	/// The channel this output belongs to.
	///
	/// Will be `None` if no `channel_id` was given to [`OutputSweeper::track_spendable_outputs`]
	pub channel_id: Option<ChannelId>,
	/// The current status of the output spend.
	pub status: OutputSpendStatus,
}

impl TrackedSpendableOutput {
	fn to_watched_output(&self, cur_hash: BlockHash) -> WatchedOutput {
		let block_hash = self.status.first_broadcast_hash().or(Some(cur_hash));
		match &self.descriptor {
			SpendableOutputDescriptor::StaticOutput { outpoint, output, channel_keys_id: _ } => {
				WatchedOutput {
					block_hash,
					outpoint: *outpoint,
					script_pubkey: output.script_pubkey.clone(),
				}
			},
			SpendableOutputDescriptor::DelayedPaymentOutput(output) => WatchedOutput {
				block_hash,
				outpoint: output.outpoint,
				script_pubkey: output.output.script_pubkey.clone(),
			},
			SpendableOutputDescriptor::StaticPaymentOutput(output) => WatchedOutput {
				block_hash,
				outpoint: output.outpoint,
				script_pubkey: output.output.script_pubkey.clone(),
			},
		}
	}

	/// Returns whether the output is spent in the given transaction.
	pub fn is_spent_in(&self, tx: &Transaction) -> bool {
		let prev_outpoint = self.descriptor.spendable_outpoint().into_bitcoin_outpoint();
		tx.input.iter().any(|input| input.previous_output == prev_outpoint)
	}
}

impl_writeable_tlv_based!(TrackedSpendableOutput, {
	(0, descriptor, required),
	(2, channel_id, option),
	(4, status, required),
});

/// The current status of the output spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSpendStatus {
	/// The output is tracked but an initial spending transaction hasn't been generated and
	/// broadcasted yet.
	PendingInitialBroadcast {
		/// The height at which we will first generate and broadcast a spending transaction.
		delayed_until_height: Option<u32>,
	},
	/// A transaction spending the output has been broadcasted but is pending its first confirmation on-chain.
	PendingFirstConfirmation {
		/// The hash of the chain tip when we first broadcast a transaction spending this output.
		first_broadcast_hash: BlockHash,
		/// The best height when we last broadcast a transaction spending this output.
		latest_broadcast_height: u32,
		/// The transaction spending this output we last broadcasted.
		latest_spending_tx: Transaction,
	},
	/// A transaction spending the output has been confirmed on-chain but will be tracked until it
	/// reaches at least [`PRUNE_DELAY_BLOCKS`] confirmations to ensure [`Event::SpendableOutputs`]
	/// stemming from lingering [`ChannelMonitor`]s can safely be replayed.
	///
	/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	PendingThresholdConfirmations {
		/// The hash of the chain tip when we first broadcast a transaction spending this output.
		first_broadcast_hash: BlockHash,
		/// The best height when we last broadcast a transaction spending this output.
		latest_broadcast_height: u32,
		/// The transaction spending this output we saw confirmed on-chain.
		latest_spending_tx: Transaction,
		/// The height at which the spending transaction was confirmed.
		confirmation_height: u32,
		/// The hash of the block in which the spending transaction was confirmed.
		confirmation_hash: BlockHash,
	},
}

impl OutputSpendStatus {
	fn broadcast(&mut self, cur_hash: BlockHash, cur_height: u32, latest_spending_tx: Transaction) {
		match self {
			Self::PendingInitialBroadcast { delayed_until_height } => {
				if let Some(delayed_until_height) = delayed_until_height {
					debug_assert!(
						cur_height >= *delayed_until_height,
						"We should never broadcast before the required height is reached."
					);
				}
				*self = Self::PendingFirstConfirmation {
					first_broadcast_hash: cur_hash,
					latest_broadcast_height: cur_height,
					latest_spending_tx,
				};
			},
			Self::PendingFirstConfirmation { first_broadcast_hash, .. } => {
				*self = Self::PendingFirstConfirmation {
					first_broadcast_hash: *first_broadcast_hash,
					latest_broadcast_height: cur_height,
					latest_spending_tx,
				};
			},
			Self::PendingThresholdConfirmations { .. } => {
				debug_assert!(false, "We should never rebroadcast confirmed transactions.");
			},
		}
	}

	fn confirmed(
		&mut self, confirmation_hash: BlockHash, confirmation_height: u32,
		latest_spending_tx: Transaction,
	) {
		match self {
			Self::PendingInitialBroadcast { .. } => {
				// Generally we can't see any of our transactions confirmed if they haven't been
				// broadcasted yet, so this should never be reachable via `transactions_confirmed`.
				debug_assert!(false, "We should never confirm when we haven't broadcasted. This a bug and should never happen, please report.");
				*self = Self::PendingThresholdConfirmations {
					first_broadcast_hash: confirmation_hash,
					latest_broadcast_height: confirmation_height,
					latest_spending_tx,
					confirmation_height,
					confirmation_hash,
				};
			},
			Self::PendingFirstConfirmation {
				first_broadcast_hash,
				latest_broadcast_height,
				..
			} => {
				*self = Self::PendingThresholdConfirmations {
					first_broadcast_hash: *first_broadcast_hash,
					latest_broadcast_height: *latest_broadcast_height,
					latest_spending_tx,
					confirmation_height,
					confirmation_hash,
				};
			},
			Self::PendingThresholdConfirmations {
				first_broadcast_hash,
				latest_broadcast_height,
				..
			} => {
				*self = Self::PendingThresholdConfirmations {
					first_broadcast_hash: *first_broadcast_hash,
					latest_broadcast_height: *latest_broadcast_height,
					latest_spending_tx,
					confirmation_height,
					confirmation_hash,
				};
			},
		}
	}

	fn unconfirmed(&mut self) {
		match self {
			Self::PendingInitialBroadcast { .. } => {
				debug_assert!(
					false,
					"We should only mark a spend as unconfirmed if it used to be confirmed."
				);
			},
			Self::PendingFirstConfirmation { .. } => {
				debug_assert!(
					false,
					"We should only mark a spend as unconfirmed if it used to be confirmed."
				);
			},
			Self::PendingThresholdConfirmations {
				first_broadcast_hash,
				latest_broadcast_height,
				latest_spending_tx,
				..
			} => {
				*self = Self::PendingFirstConfirmation {
					first_broadcast_hash: *first_broadcast_hash,
					latest_broadcast_height: *latest_broadcast_height,
					latest_spending_tx: latest_spending_tx.clone(),
				};
			},
		}
	}

	fn is_delayed(&self, cur_height: u32) -> bool {
		match self {
			Self::PendingInitialBroadcast { delayed_until_height } => {
				delayed_until_height.map_or(false, |req_height| cur_height < req_height)
			},
			Self::PendingFirstConfirmation { .. } => false,
			Self::PendingThresholdConfirmations { .. } => false,
		}
	}

	fn first_broadcast_hash(&self) -> Option<BlockHash> {
		match self {
			Self::PendingInitialBroadcast { .. } => None,
			Self::PendingFirstConfirmation { first_broadcast_hash, .. } => {
				Some(*first_broadcast_hash)
			},
			Self::PendingThresholdConfirmations { first_broadcast_hash, .. } => {
				Some(*first_broadcast_hash)
			},
		}
	}

	fn latest_broadcast_height(&self) -> Option<u32> {
		match self {
			Self::PendingInitialBroadcast { .. } => None,
			Self::PendingFirstConfirmation { latest_broadcast_height, .. } => {
				Some(*latest_broadcast_height)
			},
			Self::PendingThresholdConfirmations { latest_broadcast_height, .. } => {
				Some(*latest_broadcast_height)
			},
		}
	}

	fn confirmation_height(&self) -> Option<u32> {
		match self {
			Self::PendingInitialBroadcast { .. } => None,
			Self::PendingFirstConfirmation { .. } => None,
			Self::PendingThresholdConfirmations { confirmation_height, .. } => {
				Some(*confirmation_height)
			},
		}
	}

	fn confirmation_hash(&self) -> Option<BlockHash> {
		match self {
			Self::PendingInitialBroadcast { .. } => None,
			Self::PendingFirstConfirmation { .. } => None,
			Self::PendingThresholdConfirmations { confirmation_hash, .. } => {
				Some(*confirmation_hash)
			},
		}
	}

	fn latest_spending_tx(&self) -> Option<&Transaction> {
		match self {
			Self::PendingInitialBroadcast { .. } => None,
			Self::PendingFirstConfirmation { latest_spending_tx, .. } => Some(latest_spending_tx),
			Self::PendingThresholdConfirmations { latest_spending_tx, .. } => {
				Some(latest_spending_tx)
			},
		}
	}

	fn is_confirmed(&self) -> bool {
		match self {
			Self::PendingInitialBroadcast { .. } => false,
			Self::PendingFirstConfirmation { .. } => false,
			Self::PendingThresholdConfirmations { .. } => true,
		}
	}
}

impl_writeable_tlv_based_enum!(OutputSpendStatus,
	(0, PendingInitialBroadcast) => {
		(0, delayed_until_height, option),
	},
	(2, PendingFirstConfirmation) => {
		(0, first_broadcast_hash, required),
		(2, latest_broadcast_height, required),
		(4, latest_spending_tx, required),
	},
	(4, PendingThresholdConfirmations) => {
		(0, first_broadcast_hash, required),
		(2, latest_broadcast_height, required),
		(4, latest_spending_tx, required),
		(6, confirmation_height, required),
		(8, confirmation_hash, required),
	},
);

/// A utility that keeps track of [`SpendableOutputDescriptor`]s, persists them in a given
/// [`KVStore`] and regularly retries sweeping them based on a callback given to the constructor
/// methods.
///
/// Users should call [`Self::track_spendable_outputs`] for any [`SpendableOutputDescriptor`]s received via [`Event::SpendableOutputs`].
///
/// This needs to be notified of chain state changes either via its [`Listen`] or [`Confirm`]
/// implementation and hence has to be connected with the utilized chain data sources.
///
/// If chain data is provided via the [`Confirm`] interface or via filtered blocks, users are
/// required to give their chain data sources (i.e., [`Filter`] implementation) to the respective
/// constructor.
///
/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
pub struct OutputSweeper<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	sweeper_state: Mutex<SweeperState>,
	pending_sweep: AtomicBool,
	broadcaster: B,
	fee_estimator: E,
	chain_data_source: Option<F>,
	output_spender: O,
	change_destination_source: D,
	kv_store: K,
	logger: L,
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
	OutputSweeper<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	/// Constructs a new [`OutputSweeper`].
	///
	/// If chain data is provided via the [`Confirm`] interface or via filtered blocks, users also
	/// need to register their [`Filter`] implementation via the given `chain_data_source`.
	pub fn new(
		best_block: BestBlock, broadcaster: B, fee_estimator: E, chain_data_source: Option<F>,
		output_spender: O, change_destination_source: D, kv_store: K, logger: L,
	) -> Self {
		let outputs = Vec::new();
		let sweeper_state =
			Mutex::new(SweeperState { persistent: PersistentSweeperState { outputs, best_block } });
		Self {
			sweeper_state,
			pending_sweep: AtomicBool::new(false),
			broadcaster,
			fee_estimator,
			chain_data_source,
			output_spender,
			change_destination_source,
			kv_store,
			logger,
		}
	}

	/// Tells the sweeper to track the given outputs descriptors.
	///
	/// Usually, this should be called based on the values emitted by the
	/// [`Event::SpendableOutputs`].
	///
	/// The given `exclude_static_outputs` flag controls whether the sweeper will filter out
	/// [`SpendableOutputDescriptor::StaticOutput`]s, which may be handled directly by the on-chain
	/// wallet implementation.
	///
	/// If `delay_until_height` is set, we will delay the spending until the respective block
	/// height is reached. This can be used to batch spends, e.g., to reduce on-chain fees.
	///
	/// Returns `Err` on persistence failure, in which case the call may be safely retried.
	///
	/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
	pub fn track_spendable_outputs(
		&self, output_descriptors: Vec<SpendableOutputDescriptor>, channel_id: Option<ChannelId>,
		exclude_static_outputs: bool, delay_until_height: Option<u32>,
	) -> Result<(), ()> {
		let mut relevant_descriptors = output_descriptors
			.into_iter()
			.filter(|desc| {
				!(exclude_static_outputs
					&& matches!(desc, SpendableOutputDescriptor::StaticOutput { .. }))
			})
			.peekable();

		if relevant_descriptors.peek().is_none() {
			return Ok(());
		}

		let mut state_lock = self.sweeper_state.lock().unwrap();
		for descriptor in relevant_descriptors {
			let output_info = TrackedSpendableOutput {
				descriptor,
				channel_id,
				status: OutputSpendStatus::PendingInitialBroadcast {
					delayed_until_height: delay_until_height,
				},
			};

			let mut outputs = state_lock.persistent.outputs.iter();
			if outputs.find(|o| o.descriptor == output_info.descriptor).is_some() {
				continue;
			}

			state_lock.persistent.outputs.push(output_info);
		}
		self.persist_state(&state_lock.persistent).map_err(|e| {
			log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
		})
	}

	/// Returns a list of the currently tracked spendable outputs.
	pub fn tracked_spendable_outputs(&self) -> Vec<TrackedSpendableOutput> {
		self.sweeper_state.lock().unwrap().persistent.outputs.clone()
	}

	/// Gets the latest best block which was connected either via the [`Listen`] or
	/// [`Confirm`] interfaces.
	pub fn current_best_block(&self) -> BestBlock {
		self.sweeper_state.lock().unwrap().persistent.best_block
	}

	/// Regenerates and broadcasts the spending transaction for any outputs that are pending. This method will be a
	/// no-op if a sweep is already pending.
	pub async fn regenerate_and_broadcast_spend_if_necessary(&self) -> Result<(), ()> {
		// Prevent concurrent sweeps.
		if self
			.pending_sweep
			.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
			.is_err()
		{
			return Ok(());
		}

		let result = self.regenerate_and_broadcast_spend_if_necessary_internal().await;

		// Release the pending sweep flag again, regardless of result.
		self.pending_sweep.store(false, Ordering::Release);

		result
	}

	/// Regenerates and broadcasts the spending transaction for any outputs that are pending
	async fn regenerate_and_broadcast_spend_if_necessary_internal(&self) -> Result<(), ()> {
		let filter_fn = |o: &TrackedSpendableOutput, cur_height: u32| {
			if o.status.is_confirmed() {
				// Don't rebroadcast confirmed txs.
				return false;
			}

			if o.status.is_delayed(cur_height) {
				// Don't generate and broadcast if still delayed
				return false;
			}

			if o.status.latest_broadcast_height() >= Some(cur_height) {
				// Only broadcast once per block height.
				return false;
			}

			true
		};

		// See if there is anything to sweep before requesting a change address.
		{
			let sweeper_state = self.sweeper_state.lock().unwrap();

			let cur_height = sweeper_state.persistent.best_block.height;
			let has_respends =
				sweeper_state.persistent.outputs.iter().any(|o| filter_fn(o, cur_height));
			if !has_respends {
				return Ok(());
			}
		}

		// Request a new change address outside of the mutex to avoid the mutex crossing await.
		let change_destination_script =
			self.change_destination_source.get_change_destination_script().await?;

		// Sweep the outputs.
		{
			let mut sweeper_state = self.sweeper_state.lock().unwrap();

			let cur_height = sweeper_state.persistent.best_block.height;
			let cur_hash = sweeper_state.persistent.best_block.block_hash;

			let respend_descriptors: Vec<&SpendableOutputDescriptor> = sweeper_state
				.persistent
				.outputs
				.iter()
				.filter(|o| filter_fn(*o, cur_height))
				.map(|o| &o.descriptor)
				.collect();

			if respend_descriptors.is_empty() {
				// It could be that a tx confirmed and there is now nothing to sweep anymore.
				return Ok(());
			}

			let spending_tx = self
				.spend_outputs(
					&sweeper_state.persistent,
					&respend_descriptors,
					change_destination_script,
				)
				.map_err(|e| {
					log_error!(self.logger, "Error spending outputs: {:?}", e);
				})?;

			log_debug!(
				self.logger,
				"Generating and broadcasting sweeping transaction {}",
				spending_tx.compute_txid()
			);

			// As we didn't modify the state so far, the same filter_fn yields the same elements as
			// above.
			let respend_outputs =
				sweeper_state.persistent.outputs.iter_mut().filter(|o| filter_fn(&**o, cur_height));
			for output_info in respend_outputs {
				if let Some(filter) = self.chain_data_source.as_ref() {
					let watched_output = output_info.to_watched_output(cur_hash);
					filter.register_output(watched_output);
				}

				output_info.status.broadcast(cur_hash, cur_height, spending_tx.clone());
			}

			self.persist_state(&sweeper_state.persistent).map_err(|e| {
				log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
			})?;

			self.broadcaster.broadcast_transactions(&[&spending_tx]);
		}

		Ok(())
	}

	fn prune_confirmed_outputs(&self, sweeper_state: &mut SweeperState) {
		let cur_height = sweeper_state.persistent.best_block.height;

		// Prune all outputs that have sufficient depth by now.
		sweeper_state.persistent.outputs.retain(|o| {
			if let Some(confirmation_height) = o.status.confirmation_height() {
				// We wait at least `PRUNE_DELAY_BLOCKS` as before that
				// `Event::SpendableOutputs` from lingering monitors might get replayed.
				if cur_height >= confirmation_height + PRUNE_DELAY_BLOCKS - 1 {
					log_debug!(self.logger,
						"Pruning swept output as sufficiently confirmed via spend in transaction {:?}. Pruned descriptor: {:?}",
						o.status.latest_spending_tx().map(|t| t.compute_txid()), o.descriptor
					);
					return false;
				}
			}
			true
		});
	}

	fn persist_state(&self, sweeper_state: &PersistentSweeperState) -> Result<(), io::Error> {
		self.kv_store
			.write(
				OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
				OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
				OUTPUT_SWEEPER_PERSISTENCE_KEY,
				&sweeper_state.encode(),
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Write for key {}/{}/{} failed due to: {}",
					OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
					OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
					OUTPUT_SWEEPER_PERSISTENCE_KEY,
					e
				);
				e
			})
	}

	fn spend_outputs(
		&self, sweeper_state: &PersistentSweeperState, descriptors: &[&SpendableOutputDescriptor],
		change_destination_script: ScriptBuf,
	) -> Result<Transaction, ()> {
		let tx_feerate =
			self.fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::OutputSpendingFee);
		let cur_height = sweeper_state.best_block.height;
		let locktime = Some(LockTime::from_height(cur_height).unwrap_or(LockTime::ZERO));
		self.output_spender.spend_spendable_outputs(
			descriptors,
			Vec::new(),
			change_destination_script,
			tx_feerate,
			locktime,
			&Secp256k1::new(),
		)
	}

	fn transactions_confirmed_internal(
		&self, sweeper_state: &mut SweeperState, header: &Header,
		txdata: &chain::transaction::TransactionData, height: u32,
	) {
		let confirmation_hash = header.block_hash();
		for (_, tx) in txdata {
			for output_info in sweeper_state.persistent.outputs.iter_mut() {
				if output_info.is_spent_in(*tx) {
					output_info.status.confirmed(confirmation_hash, height, (*tx).clone())
				}
			}
		}
	}

	fn best_block_updated_internal(
		&self, sweeper_state: &mut SweeperState, header: &Header, height: u32,
	) {
		sweeper_state.persistent.best_block = BestBlock::new(header.block_hash(), height);
		self.prune_confirmed_outputs(sweeper_state);
	}
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref> Listen
	for OutputSweeper<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	fn filtered_block_connected(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		let mut state_lock = self.sweeper_state.lock().unwrap();
		assert_eq!(state_lock.persistent.best_block.block_hash, header.prev_blockhash,
			"Blocks must be connected in chain-order - the connected header must build on the last connected header");
		assert_eq!(state_lock.persistent.best_block.height, height - 1,
			"Blocks must be connected in chain-order - the connected block height must be one greater than the previous height");

		self.transactions_confirmed_internal(&mut *state_lock, header, txdata, height);
		self.best_block_updated_internal(&mut *state_lock, header, height);

		let _ = self.persist_state(&state_lock.persistent).map_err(|e| {
			log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
		});
	}

	fn block_disconnected(&self, header: &Header, height: u32) {
		let mut state_lock = self.sweeper_state.lock().unwrap();

		let new_height = height - 1;
		let block_hash = header.block_hash();

		assert_eq!(state_lock.persistent.best_block.block_hash, block_hash,
		"Blocks must be disconnected in chain-order - the disconnected header must be the last connected header");
		assert_eq!(state_lock.persistent.best_block.height, height,
			"Blocks must be disconnected in chain-order - the disconnected block must have the correct height");
		state_lock.persistent.best_block = BestBlock::new(header.prev_blockhash, new_height);

		for output_info in state_lock.persistent.outputs.iter_mut() {
			if output_info.status.confirmation_hash() == Some(block_hash) {
				debug_assert_eq!(output_info.status.confirmation_height(), Some(height));
				output_info.status.unconfirmed();
			}
		}

		self.persist_state(&state_lock.persistent).unwrap_or_else(|e| {
			log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
		});
	}
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref> Confirm
	for OutputSweeper<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	fn transactions_confirmed(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		let mut state_lock = self.sweeper_state.lock().unwrap();
		self.transactions_confirmed_internal(&mut *state_lock, header, txdata, height);
		self.persist_state(&state_lock.persistent).unwrap_or_else(|e| {
			log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
		});
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let mut state_lock = self.sweeper_state.lock().unwrap();

		// Get what height was unconfirmed.
		let unconf_height = state_lock
			.persistent
			.outputs
			.iter()
			.find(|o| o.status.latest_spending_tx().map(|tx| tx.compute_txid()) == Some(*txid))
			.and_then(|o| o.status.confirmation_height());

		if let Some(unconf_height) = unconf_height {
			// Unconfirm all >= this height.
			state_lock
				.persistent
				.outputs
				.iter_mut()
				.filter(|o| o.status.confirmation_height() >= Some(unconf_height))
				.for_each(|o| o.status.unconfirmed());

			self.persist_state(&state_lock.persistent).unwrap_or_else(|e| {
				log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
			});
		}
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		let mut state_lock = self.sweeper_state.lock().unwrap();
		self.best_block_updated_internal(&mut *state_lock, header, height);
		let _ = self.persist_state(&state_lock.persistent).map_err(|e| {
			log_error!(self.logger, "Error persisting OutputSweeper: {:?}", e);
		});
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let state_lock = self.sweeper_state.lock().unwrap();
		state_lock
			.persistent
			.outputs
			.iter()
			.filter_map(|o| match o.status {
				OutputSpendStatus::PendingThresholdConfirmations {
					ref latest_spending_tx,
					confirmation_height,
					confirmation_hash,
					..
				} => Some((
					latest_spending_tx.compute_txid(),
					confirmation_height,
					Some(confirmation_hash),
				)),
				_ => None,
			})
			.collect::<Vec<_>>()
	}
}

#[derive(Debug)]
struct SweeperState {
	persistent: PersistentSweeperState,
}

#[derive(Debug, Clone)]
struct PersistentSweeperState {
	outputs: Vec<TrackedSpendableOutput>,
	best_block: BestBlock,
}

impl_writeable_tlv_based!(PersistentSweeperState, {
	(0, outputs, required_vec),
	(2, best_block, required),
});

/// A `enum` signalling to the [`OutputSweeper`] that it should delay spending an output until a
/// future block height is reached.
#[derive(Debug, Clone)]
pub enum SpendingDelay {
	/// A relative delay indicating we shouldn't spend the output before `cur_height + num_blocks`
	/// is reached.
	Relative {
		/// The number of blocks until we'll generate and broadcast the spending transaction.
		num_blocks: u32,
	},
	/// An absolute delay indicating we shouldn't spend the output before `height` is reached.
	Absolute {
		/// The height at which we'll generate and broadcast the spending transaction.
		height: u32,
	},
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
	ReadableArgs<(B, E, Option<F>, O, D, K, L)> for OutputSweeper<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	#[inline]
	fn read<R: io::Read>(
		reader: &mut R, args: (B, E, Option<F>, O, D, K, L),
	) -> Result<Self, DecodeError> {
		let (
			broadcaster,
			fee_estimator,
			chain_data_source,
			output_spender,
			change_destination_source,
			kv_store,
			logger,
		) = args;
		let state = PersistentSweeperState::read(reader)?;
		let best_block = state.best_block;

		if let Some(filter) = chain_data_source.as_ref() {
			for output_info in &state.outputs {
				let watched_output = output_info.to_watched_output(best_block.block_hash);
				filter.register_output(watched_output);
			}
		}

		let sweeper_state = Mutex::new(SweeperState { persistent: state });
		Ok(Self {
			sweeper_state,
			pending_sweep: AtomicBool::new(false),
			broadcaster,
			fee_estimator,
			chain_data_source,
			output_spender,
			change_destination_source,
			kv_store,
			logger,
		})
	}
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
	ReadableArgs<(B, E, Option<F>, O, D, K, L)> for (BestBlock, OutputSweeper<B, D, E, F, K, L, O>)
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSource,
	E::Target: FeeEstimator,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	#[inline]
	fn read<R: io::Read>(
		reader: &mut R, args: (B, E, Option<F>, O, D, K, L),
	) -> Result<Self, DecodeError> {
		let (
			broadcaster,
			fee_estimator,
			chain_data_source,
			output_spender,
			change_destination_source,
			kv_store,
			logger,
		) = args;
		let state = PersistentSweeperState::read(reader)?;
		let best_block = state.best_block;

		if let Some(filter) = chain_data_source.as_ref() {
			for output_info in &state.outputs {
				let watched_output = output_info.to_watched_output(best_block.block_hash);
				filter.register_output(watched_output);
			}
		}

		let sweeper_state = Mutex::new(SweeperState { persistent: state });
		Ok((
			best_block,
			OutputSweeper {
				sweeper_state,
				pending_sweep: AtomicBool::new(false),
				broadcaster,
				fee_estimator,
				chain_data_source,
				output_spender,
				change_destination_source,
				kv_store,
				logger,
			},
		))
	}
}

/// A synchronous wrapper around [`OutputSweeper`] to be used in contexts where async is not available.
pub struct OutputSweeperSync<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSourceSync,
	E::Target: FeeEstimator,
	F::Target: Filter,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	sweeper: Arc<OutputSweeper<B, Arc<ChangeDestinationSourceSyncWrapper<D>>, E, F, K, L, O>>,
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref>
	OutputSweeperSync<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSourceSync,
	E::Target: FeeEstimator,
	F::Target: Filter,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	/// Constructs a new [`OutputSweeperSync`] instance.
	pub fn new(
		best_block: BestBlock, broadcaster: B, fee_estimator: E, chain_data_source: Option<F>,
		output_spender: O, change_destination_source: D, kv_store: K, logger: L,
	) -> Self {
		let change_destination_source =
			Arc::new(ChangeDestinationSourceSyncWrapper::new(change_destination_source));

		let sweeper = OutputSweeper::new(
			best_block,
			broadcaster,
			fee_estimator,
			chain_data_source,
			output_spender,
			change_destination_source,
			kv_store,
			logger,
		);
		Self { sweeper: Arc::new(sweeper) }
	}

	/// Regenerates and broadcasts the spending transaction for any outputs that are pending. Wraps
	/// [`OutputSweeper::regenerate_and_broadcast_spend_if_necessary`].
	pub fn regenerate_and_broadcast_spend_if_necessary(&self) -> Result<(), ()> {
		let mut fut = Box::pin(self.sweeper.regenerate_and_broadcast_spend_if_necessary());
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("OutputSweeper::regenerate_and_broadcast_spend_if_necessary should not be pending in a sync context");
			},
		}
	}

	/// Tells the sweeper to track the given outputs descriptors. Wraps [`OutputSweeper::track_spendable_outputs`].
	pub fn track_spendable_outputs(
		&self, output_descriptors: Vec<SpendableOutputDescriptor>, channel_id: Option<ChannelId>,
		exclude_static_outputs: bool, delay_until_height: Option<u32>,
	) -> Result<(), ()> {
		self.sweeper.track_spendable_outputs(
			output_descriptors,
			channel_id,
			exclude_static_outputs,
			delay_until_height,
		)
	}

	/// Returns a list of the currently tracked spendable outputs. Wraps [`OutputSweeper::tracked_spendable_outputs`].
	pub fn tracked_spendable_outputs(&self) -> Vec<TrackedSpendableOutput> {
		self.sweeper.tracked_spendable_outputs()
	}

	/// Returns the inner async sweeper for testing purposes.
	#[cfg(any(test, feature = "_test_utils"))]
	pub fn sweeper_async(
		&self,
	) -> Arc<OutputSweeper<B, Arc<ChangeDestinationSourceSyncWrapper<D>>, E, F, K, L, O>> {
		self.sweeper.clone()
	}
}

impl<B: Deref, D: Deref, E: Deref, F: Deref, K: Deref, L: Deref, O: Deref> Confirm
	for OutputSweeperSync<B, D, E, F, K, L, O>
where
	B::Target: BroadcasterInterface,
	D::Target: ChangeDestinationSourceSync,
	E::Target: FeeEstimator,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
	O::Target: OutputSpender,
{
	fn transactions_confirmed(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		self.sweeper.transactions_confirmed(header, txdata, height)
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		self.sweeper.transaction_unconfirmed(txid)
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		self.sweeper.best_block_updated(header, height);
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		self.sweeper.get_relevant_txids()
	}
}
