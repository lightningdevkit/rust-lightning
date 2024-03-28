// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains an [`OutputSweeper`] utility that keeps track of
//! [`SpendableOutputDescriptor`]s, i.e., persists them in a given [`KVStore`] and regularly retries
//! sweeping them.

use crate::chain::chaininterface::BroadcasterInterface;
use crate::chain::channelmonitor::ANTI_REORG_DELAY;
use crate::chain::{self, BestBlock, Confirm, Filter, Listen, WatchedOutput};
use crate::io;
use crate::ln::ChannelId;
use crate::prelude::{Box, String, Vec};
use crate::sign::{EntropySource, SpendableOutputDescriptor};
use crate::sync::Mutex;
use crate::util::logger::Logger;
use crate::util::persist::{
	KVStore, SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
	SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::util::ser::{Readable, Writeable};
use crate::{impl_writeable_tlv_based, log_debug, log_error};

use bitcoin::blockdata::block::Header;
use bitcoin::{BlockHash, Transaction, Txid};

use core::cmp;
use core::fmt::Write;
use core::ops::Deref;

/// The default interval in blocks after which we regenerate output spending transactions.
pub const DEFAULT_REGENERATE_SPEND_THRESHOLD: u32 = 144;

/// The state of a spendable output currently tracked by an [`OutputSweeper`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedSpendableOutput {
	/// The output's unique identifier.
	///
	/// A hex-encoding of this field is used as a key for serialization.
	id: [u8; 32],
	/// The tracked output descriptor.
	pub descriptor: SpendableOutputDescriptor,
	/// The channel this output belongs to.
	///
	/// Will be `None` if no `channel_id` was given to [`OutputSweeper::track_spendable_outputs`]
	pub channel_id: Option<ChannelId>,
	/// The hash of the chain tip when we first broadcast a transaction spending this output.
	///
	/// Will be `None` if it hasn't been broadcast yet.
	pub first_broadcast_hash: Option<BlockHash>,
	/// The best height when we last broadcast a transaction spending this output.
	///
	/// Will be `None` if it hasn't been broadcast yet.
	pub latest_broadcast_height: Option<u32>,
	/// The best height when we last (re-)generated a transaction spending this output.
	///
	/// Will be `None` if no transaction has been generated yet.
	pub latest_spend_generation_height: Option<u32>,
	/// The transaction spending this output we last broadcast.
	///
	/// After confirmation, this will be set to the confirmed transaction.
	///
	/// Will be `None` if it hasn't been broadcast yet.
	pub latest_spending_tx: Option<Transaction>,
	/// The height at which the spending transaction was confirmed.
	///
	/// Will be `None` if it hasn't been confirmed yet.
	pub confirmation_height: Option<u32>,
	/// The hash of the block in which the spending transaction was confirmed.
	///
	/// Will be `None` if it hasn't been confirmed yet.
	pub confirmation_hash: Option<BlockHash>,
}

impl TrackedSpendableOutput {
	fn to_watched_output(&self) -> WatchedOutput {
		match &self.descriptor {
			SpendableOutputDescriptor::StaticOutput { outpoint, output, channel_keys_id: _ } => {
				WatchedOutput {
					block_hash: self.first_broadcast_hash,
					outpoint: *outpoint,
					script_pubkey: output.script_pubkey.clone(),
				}
			},
			SpendableOutputDescriptor::DelayedPaymentOutput(output) => WatchedOutput {
				block_hash: self.first_broadcast_hash,
				outpoint: output.outpoint,
				script_pubkey: output.output.script_pubkey.clone(),
			},
			SpendableOutputDescriptor::StaticPaymentOutput(output) => WatchedOutput {
				block_hash: self.first_broadcast_hash,
				outpoint: output.outpoint,
				script_pubkey: output.output.script_pubkey.clone(),
			},
		}
	}

	fn is_spent_in(&self, tx: &Transaction) -> bool {
		let prev_outpoint = match &self.descriptor {
			SpendableOutputDescriptor::StaticOutput { outpoint, .. } => *outpoint,
			SpendableOutputDescriptor::DelayedPaymentOutput(output) => output.outpoint,
			SpendableOutputDescriptor::StaticPaymentOutput(output) => output.outpoint,
		}
		.into_bitcoin_outpoint();

		tx.input.iter().any(|input| input.previous_output == prev_outpoint)
	}
}

impl_writeable_tlv_based!(TrackedSpendableOutput, {
	(0, id, required),
	(1, latest_spend_generation_height, option),
	(2, descriptor, required),
	(4, channel_id, option),
	(6, first_broadcast_hash, option),
	(8, latest_broadcast_height, option),
	(10, latest_spending_tx, option),
	(12, confirmation_height, option),
	(14, confirmation_hash, option),
});

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
pub struct OutputSweeper<B: Deref, ES: Deref, F: Deref, K: Deref, L: Deref>
where
	B::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
{
	outputs: Mutex<Vec<TrackedSpendableOutput>>,
	broadcaster: B,
	entropy_source: ES,
	kv_store: K,
	best_block: Mutex<BestBlock>,
	chain_data_source: Option<F>,
	logger: L,
	regenerate_spend_threshold: u32,
	spend_outputs_callback: Box<
		dyn Fn(&[&SpendableOutputDescriptor]) -> Result<Transaction, ()> + Send + Sync + 'static,
	>,
}

impl<B: Deref, ES: Deref, F: Deref, K: Deref, L: Deref> OutputSweeper<B, ES, F, K, L>
where
	B::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
{
	/// Constructs a new [`OutputSweeper`].
	///
	/// If chain data is provided via the [`Confirm`] interface or via filtered blocks, users also
	/// need to register their [`Filter`] implementation via the given `chain_data_source`.
	///
	/// The given `regenerate_spend_threshold` allows to override the interval in which the sweeper
	/// will regenerate new spending transactions using updated fee estimates. If set to `Some`, a
	/// minimum of [`ANTI_REORG_DELAY`] will always be enforced. If set to `None`, the
	/// [`DEFAULT_REGENERATE_SPEND_THRESHOLD`] will be used.
	///
	/// The given `spend_outputs_callback` is a function takes a list of
	/// [`SpendableOutputDescriptor`] and returns a fully signed ready-for-broadcast
	/// [`Transaction`]. Usually, this should retrieve a change address from the on-chain wallet
	/// and call [`KeysManager::spend_spendable_outputs`].
	///
	/// [`KeysManager::spend_spendable_outputs`]: crate::sign::KeysManager::spend_spendable_outputs
	///
	/// #### Example:
	/// ```
	/// # use bitcoin::key::Secp256k1;
	/// # use bitcoin::{Network, Script, ScriptBuf, Transaction, Txid};
	/// # use std::sync::Arc;
	/// # use lightning::sign::SpendableOutputDescriptor;
	/// # use lightning::sign::KeysManager;
	/// # use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator, BroadcasterInterface};
	/// # use lightning::chain::{BestBlock, Filter, WatchedOutput};
	/// # use lightning::util::persist::KVStore;
	/// # use lightning::util::sweep::OutputSweeper;
	/// # use lightning::util::logger::{Logger, Record};
	/// # use lightning::io;
	/// # struct MyWallet {}
	/// # impl MyWallet {
	/// #     fn get_new_address(&self) -> ScriptBuf { ScriptBuf::new() }
	/// # }
	/// # fn example<K: KVStore, E: FeeEstimator + Send + Sync + 'static, B: BroadcasterInterface,
	/// #     F: Filter + Sync + Send, L: Logger>
	/// # (
	/// #     store: Arc<K>, fee_estimator: Arc<E>, broadcaster: Arc<B>, chain_data_source: Arc<F>,
	/// #     logger: Arc<L>
	/// # ) {
	/// # let wallet = Arc::new(MyWallet{});
	/// # let keys_manager = Arc::new(KeysManager::new(&[42u8; 32], 0, 0));
	/// # let best_block = BestBlock::from_network(Network::Regtest);
	/// let spend_wallet = Arc::clone(&wallet);
	/// let spend_keys_manager = Arc::clone(&keys_manager);
	/// let spend_fee_estimator = Arc::clone(&fee_estimator);
	/// let spend_outputs_callback = move |output_descriptors: &[&SpendableOutputDescriptor]| {
	/// 	let change_destination_script = spend_wallet.get_new_address();
	/// 	let fee_rate = spend_fee_estimator.get_est_sat_per_1000_weight(
	/// 		ConfirmationTarget::NonAnchorChannelFee
	/// 	);
	/// 	spend_keys_manager.spend_spendable_outputs(
	/// 		output_descriptors,
	/// 		Vec::new(),
	/// 		change_destination_script,
	/// 		fee_rate,
	/// 		None,
	/// 		&Secp256k1::new(),
	/// 	)
	/// };
	///
	/// let regenerate_spend_threshold = None;
	/// let sweeper = OutputSweeper::new(broadcaster, keys_manager, store, best_block,
	/// 	Some(chain_data_source), logger, regenerate_spend_threshold, spend_outputs_callback
	/// );
	/// # }
	///```
	pub fn new(
		broadcaster: B, entropy_source: ES, kv_store: K, best_block: BestBlock,
		chain_data_source: Option<F>, logger: L, regenerate_spend_threshold: Option<u32>,
		spend_outputs_callback: impl Fn(&[&SpendableOutputDescriptor]) -> Result<Transaction, ()>
			+ Send
			+ Sync
			+ 'static,
	) -> Self {
		let outputs = Vec::new();
		Self::from_outputs(
			outputs,
			broadcaster,
			entropy_source,
			kv_store,
			best_block,
			chain_data_source,
			logger,
			regenerate_spend_threshold,
			spend_outputs_callback,
		)
	}

	/// Constructs an [`OutputSweeper`] from the given list of [`TrackedSpendableOutput`]s.
	///
	/// Outputs may be read from the given [`KVStore`] via [`read_spendable_outputs`].
	///
	/// See [`Self::new`] for more information regarding the remaining arguments.
	pub fn from_outputs(
		outputs: Vec<TrackedSpendableOutput>, broadcaster: B, entropy_source: ES, kv_store: K,
		best_block: BestBlock, chain_data_source: Option<F>, logger: L,
		regenerate_spend_threshold: Option<u32>,
		spend_outputs_callback: impl Fn(&[&SpendableOutputDescriptor]) -> Result<Transaction, ()>
			+ Send
			+ Sync
			+ 'static,
	) -> Self {
		if let Some(filter) = chain_data_source.as_ref() {
			for output_info in &outputs {
				let watched_output = output_info.to_watched_output();
				filter.register_output(watched_output);
			}
		}

		let outputs = Mutex::new(outputs);
		let best_block = Mutex::new(best_block);
		let regenerate_spend_threshold = regenerate_spend_threshold
			.map(|threshold| cmp::max(threshold, ANTI_REORG_DELAY))
			.unwrap_or(DEFAULT_REGENERATE_SPEND_THRESHOLD);
		let spend_outputs_callback = Box::new(spend_outputs_callback);
		Self {
			outputs,
			broadcaster,
			entropy_source,
			kv_store,
			best_block,
			chain_data_source,
			logger,
			spend_outputs_callback,
			regenerate_spend_threshold,
		}
	}

	/// Tells the sweeper to track the given outputs descriptors.
	///
	/// Usually, this should be called based on the values emitted by the
	/// [`Event::SpendableOutputs`].
	///
	/// The given `exclude_static_ouputs` flag controls whether the sweeper will filter out
	/// [`SpendableOutputDescriptor::StaticOutput`]s, which may be handled directly by the on-chain
	/// wallet implementation.
	///
	/// [`Event::SpendableOutputs`]: crate::events::Event::SpendableOutputs
	pub fn track_spendable_outputs(
		&self, output_descriptors: Vec<SpendableOutputDescriptor>, channel_id: Option<ChannelId>,
		exclude_static_ouputs: bool,
	) {
		let mut relevant_descriptors = output_descriptors
			.into_iter()
			.filter(|desc| {
				!(exclude_static_ouputs
					&& matches!(desc, SpendableOutputDescriptor::StaticOutput { .. }))
			})
			.peekable();

		if relevant_descriptors.peek().is_none() {
			return;
		}

		{
			let mut locked_outputs = self.outputs.lock().unwrap();
			for descriptor in relevant_descriptors {
				let id = self.entropy_source.get_secure_random_bytes();
				let output_info = TrackedSpendableOutput {
					id,
					descriptor,
					channel_id,
					first_broadcast_hash: None,
					latest_broadcast_height: None,
					latest_spend_generation_height: None,
					latest_spending_tx: None,
					confirmation_height: None,
					confirmation_hash: None,
				};

				if locked_outputs.iter().find(|o| o.descriptor == output_info.descriptor).is_some()
				{
					continue;
				}

				self.persist_info(&output_info).unwrap_or_else(|e| {
					log_error!(self.logger, "Error persisting TrackedSpendableOutput: {:?}", e);
				});
				locked_outputs.push(output_info);
			}
		}

		self.rebroadcast_if_necessary();
	}

	/// Returns a list of the currently tracked spendable outputs.
	pub fn tracked_spendable_outputs(&self) -> Vec<TrackedSpendableOutput> {
		self.outputs.lock().unwrap().clone()
	}

	fn rebroadcast_if_necessary(&self) {
		let (cur_height, cur_hash) = {
			let best_block = self.best_block.lock().unwrap();
			(best_block.height, best_block.block_hash)
		};

		let mut respend_descriptors_and_ids = Vec::new();

		{
			let mut locked_outputs = self.outputs.lock().unwrap();
			for output_info in locked_outputs.iter_mut() {
				if output_info.confirmation_height.is_some() {
					// Don't rebroadcast confirmed txs
					debug_assert!(output_info.confirmation_hash.is_some());
					continue;
				}

				if let Some(latest_spend_generation_height) =
					output_info.latest_spend_generation_height
				{
					debug_assert!(
						output_info.latest_broadcast_height.is_some(),
						"If we had spent before, we should have broadcast, too."
					);
					debug_assert!(
						output_info.latest_spending_tx.is_some(),
						"If we had spent before, we should have a spending_tx set."
					);

					// Re-generate spending tx after regenerate_spend_threshold, rebroadcast
					// after every block
					if latest_spend_generation_height + self.regenerate_spend_threshold
						<= cur_height
					{
						log_debug!(self.logger,
							"Regeneration threshold was reached, will regenerate sweeping transaction.");

						respend_descriptors_and_ids
							.push((output_info.descriptor.clone(), output_info.id));
					} else if output_info.latest_broadcast_height < Some(cur_height) {
						if let Some(latest_spending_tx) = output_info.latest_spending_tx.as_ref() {
							log_debug!(
								self.logger,
								"Rebroadcasting output sweeping transaction {}",
								latest_spending_tx.txid()
							);
							output_info.latest_broadcast_height = Some(cur_height);
							self.persist_info(&output_info).unwrap_or_else(|e| {
								log_error!(
									self.logger,
									"Error persisting TrackedSpendableOutput: {:?}",
									e
								);
							});
							self.broadcaster.broadcast_transactions(&[&latest_spending_tx]);
						}
					}
				} else {
					// Our first spend generation + broadcast, will be updated and peristed below.
					respend_descriptors_and_ids
						.push((output_info.descriptor.clone(), output_info.id));
				}
			}
		}

		if !respend_descriptors_and_ids.is_empty() {
			let respend_descriptors = respend_descriptors_and_ids
				.iter()
				.map(|(d, _)| d)
				.collect::<Vec<&SpendableOutputDescriptor>>();
			match (self.spend_outputs_callback)(&respend_descriptors) {
				Ok(spending_tx) => {
					log_debug!(
						self.logger,
						"Generating and broadcasting sweeping transaction {}",
						spending_tx.txid()
					);
					let mut locked_outputs = self.outputs.lock().unwrap();
					for output_info in locked_outputs.iter_mut() {
						if respend_descriptors_and_ids
							.iter()
							.find(|(_, id)| id == &output_info.id)
							.is_some()
						{
							if let Some(filter) = self.chain_data_source.as_ref() {
								let watched_output = output_info.to_watched_output();
								filter.register_output(watched_output);
							}

							if output_info.first_broadcast_hash.is_none() {
								// Our first spend generation + broadcast.
								output_info.first_broadcast_hash = Some(cur_hash);
							}
							output_info.latest_spending_tx = Some(spending_tx.clone());
							output_info.latest_broadcast_height = Some(cur_height);
							output_info.latest_spend_generation_height = Some(cur_height);

							self.persist_info(&output_info).unwrap_or_else(|e| {
								log_error!(
									self.logger,
									"Error persisting TrackedSpendableOutput: {:?}",
									e
								);
							});
						}
					}
					self.broadcaster.broadcast_transactions(&[&spending_tx]);
				},
				Err(e) => {
					log_error!(self.logger, "Error spending outputs: {:?}", e);
				},
			};
		}
	}

	fn prune_confirmed_outputs(&self) {
		let cur_height = self.best_block.lock().unwrap().height;
		let mut locked_outputs = self.outputs.lock().unwrap();

		// Prune all outputs that have sufficient depth by now.
		locked_outputs.retain(|o| {
			if let Some(confirmation_height) = o.confirmation_height {
				if cur_height >= confirmation_height + ANTI_REORG_DELAY - 1 {
					let key = id_to_hex_string(&o.id);
					match self.kv_store.remove(
						SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
						SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
						&key,
						false,
					) {
						Ok(_) => {
							log_debug!(self.logger, "Pruning swept output as sufficiently confirmed via spend in transaction {:?}",
								o.latest_spending_tx.as_ref().map(|t| t.txid()));
							return false;
						}
						Err(e) => {
							log_error!(
								self.logger,
								"Removal of key {}/{}/{} failed due to: {}",
								SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
								SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
								key,
								e
							);
							return true;
						}
					}
				}
			}
			true
		});
	}

	fn persist_info(&self, output: &TrackedSpendableOutput) -> Result<(), io::Error> {
		let key = id_to_hex_string(&output.id);
		let data = output.encode();
		self.kv_store
			.write(
				SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
				SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
				&key,
				&data,
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Write for key {}/{}/{} failed due to: {}",
					SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
					SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
					key,
					e
				);
				e
			})
	}
}

impl<B: Deref, ES: Deref, F: Deref, K: Deref, L: Deref> Listen for OutputSweeper<B, ES, F, K, L>
where
	B::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
{
	fn filtered_block_connected(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		{
			let best_block = self.best_block.lock().unwrap();
			assert_eq!(best_block.block_hash, header.prev_blockhash,
			"Blocks must be connected in chain-order - the connected header must build on the last connected header");
			assert_eq!(best_block.height, height - 1,
			"Blocks must be connected in chain-order - the connected block height must be one greater than the previous height");
		}

		self.transactions_confirmed(header, txdata, height);
		self.best_block_updated(header, height);
	}

	fn block_disconnected(&self, header: &Header, height: u32) {
		let new_height = height - 1;
		{
			let mut best_block = self.best_block.lock().unwrap();
			assert_eq!(best_block.block_hash, header.block_hash(),
				"Blocks must be disconnected in chain-order - the disconnected header must be the last connected header");
			assert_eq!(best_block.height, height,
				"Blocks must be disconnected in chain-order - the disconnected block must have the correct height");
			*best_block = BestBlock::new(header.prev_blockhash, new_height)
		}

		let mut locked_outputs = self.outputs.lock().unwrap();
		let block_hash = header.block_hash();
		for output_info in locked_outputs.iter_mut() {
			if output_info.confirmation_hash == Some(block_hash) {
				debug_assert_eq!(output_info.confirmation_height, Some(height));
				output_info.confirmation_hash = None;
				output_info.confirmation_height = None;
				self.persist_info(&output_info).unwrap_or_else(|e| {
					log_error!(self.logger, "Error persisting TrackedSpendableOutput: {:?}", e);
				});
			}
		}
	}
}

impl<B: Deref, ES: Deref, F: Deref, K: Deref, L: Deref> Confirm for OutputSweeper<B, ES, F, K, L>
where
	B::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	F::Target: Filter + Sync + Send,
	K::Target: KVStore,
	L::Target: Logger,
{
	fn transactions_confirmed(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		let mut locked_outputs = self.outputs.lock().unwrap();
		for (_, tx) in txdata {
			for output_info in locked_outputs.iter_mut() {
				if output_info.is_spent_in(*tx) {
					debug_assert!(Some(height) > output_info.latest_broadcast_height);
					output_info.confirmation_hash = Some(header.block_hash());
					output_info.confirmation_height = Some(height);
					output_info.latest_spending_tx = Some((*tx).clone());
					self.persist_info(&output_info).unwrap_or_else(|e| {
						log_error!(self.logger, "Error persisting TrackedSpendableOutput: {:?}", e);
					});
				}
			}
		}
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let mut locked_outputs = self.outputs.lock().unwrap();

		// Get what height was unconfirmed.
		let unconf_height = locked_outputs
			.iter()
			.find(|o| o.latest_spending_tx.as_ref().map(|tx| tx.txid()) == Some(*txid))
			.and_then(|o| o.confirmation_height);

		// Unconfirm all >= this height.
		locked_outputs.iter_mut().filter(|o| o.confirmation_height >= unconf_height).for_each(
			|o| {
				o.confirmation_hash = None;
				o.confirmation_height = None;
				self.persist_info(&o).unwrap_or_else(|e| {
					log_error!(self.logger, "Error persisting TrackedSpendableOutput: {:?}", e);
				});
			},
		);
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		*self.best_block.lock().unwrap() = BestBlock::new(header.block_hash(), height);
		self.prune_confirmed_outputs();
		self.rebroadcast_if_necessary();
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let locked_outputs = self.outputs.lock().unwrap();
		locked_outputs
			.iter()
			.filter_map(|o| {
				if let Some(confirmation_hash) = o.confirmation_hash {
					if let Some(confirmation_height) = o.confirmation_height {
						if let Some(latest_spending_tx) = o.latest_spending_tx.as_ref() {
							return Some((
								latest_spending_tx.txid(),
								confirmation_height,
								Some(confirmation_hash),
							));
						}
					}
				}

				None
			})
			.collect::<Vec<_>>()
	}
}

/// Reads previously persisted spendable output information from the store.
pub fn read_spendable_outputs<K: Deref, L: Deref>(
	kv_store: K, logger: L,
) -> Result<Vec<TrackedSpendableOutput>, io::Error>
where
	K::Target: KVStore,
	L::Target: Logger,
{
	let mut res = Vec::new();

	for stored_key in kv_store.list(
		SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
		SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
	)? {
		let mut reader = io::Cursor::new(kv_store.read(
			SPENDABLE_OUTPUT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			SPENDABLE_OUTPUT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			&stored_key,
		)?);
		let output = TrackedSpendableOutput::read(&mut reader).map_err(|e| {
			log_error!(logger, "Failed to deserialize TrackedSpendableOutput: {}", e);
			io::Error::new(
				io::ErrorKind::InvalidData,
				"Failed to deserialize TrackedSpendableOutput",
			)
		})?;
		res.push(output);
	}
	Ok(res)
}

#[inline]
fn id_to_hex_string(value: &[u8]) -> String {
	let mut res = String::with_capacity(2 * value.len());
	for v in value {
		write!(&mut res, "{:02x}", v).expect("Unable to write");
	}
	res
}
